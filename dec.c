#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <time.h>

#include "bswabe.h"
#include "common.h"
#include "hmac256.h"

char* usage =
"Usage: cpabe-dec [OPTION ...] PUB_KEY PRIV_KEY FILE\n"
"\n"
"Decrypt FILE using private key PRIV_KEY and assuming public key\n"
"PUB_KEY. If the name of FILE is X.cpabe, the decrypted file will\n"
"be written as X and FILE will be removed. Otherwise the file will be\n"
"decrypted in place. Use of the -o option overrides this\n"
"behavior.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write output to FILE\n\n"
" -y, --key KEY            hmac256 key\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
/* " -s, --no-opt-sat         pick an arbitrary way of satisfying the policy\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -n, --naive-dec          use slower decryption algorithm\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -f, --flatten            use slightly different decryption algorithm\n" */
/* "                          (may result in higher or lower performance)\n\n" */
/* " -r, --report-ops         report numbers of group operations\n" */
/* "                          (only for performance evaluation)\n\n" */
"";

/* enum { */
/*  DEC_NAIVE, */
/*  DEC_FLATTEN, */
/*  DEC_MERGE, */
/* } dec_strategy = DEC_MERGE;       */

char* pub_file   = 0;
char* prv_file   = 0;
char* in_file    = 0;
char* out_file   = 0;
char* hmac_key   = 0;
/* int   no_opt_sat = 0; */
/* int   report_ops = 0; */
int   keep       = 0;

/* int num_pairings = 0; */
/* int num_exps     = 0; */
/* int num_muls     = 0; */

void
parse_args( int argc, char** argv )
{
    int i;

    for( i = 1; i < argc; i++ )
        if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
        {
            printf("%s", usage);
            exit(0);
        }
        else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
        {
            printf(CPABE_VERSION, "-dec");
            exit(0);
        }
        else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
        {
            keep = 1;
        }
        else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
        {
            if( ++i >= argc )
                die(usage);
            else
                out_file = argv[i];
        }
        else if (!strcmp(argv[i], "-y") || !strcmp(argv[i], "--key"))
        {
            if (++i >= argc)
                die(usage);
            else
                hmac_key = argv[i];
        }
        else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
        {
            pbc_random_set_deterministic(0);
        }
/*      else if( !strcmp(argv[i], "-s") || !strcmp(argv[i], "--no-opt-sat") ) */
/*      { */
/*          no_opt_sat = 1; */
/*      } */
/*      else if( !strcmp(argv[i], "-n") || !strcmp(argv[i], "--naive-dec") ) */
/*      { */
/*          dec_strategy = DEC_NAIVE; */
/*      } */
/*      else if( !strcmp(argv[i], "-f") || !strcmp(argv[i], "--flatten") ) */
/*      { */
/*          dec_strategy = DEC_FLATTEN; */
/*      } */
/*      else if( !strcmp(argv[i], "-r") || !strcmp(argv[i], "--report-ops") ) */
/*      { */
/*          report_ops = 1; */
/*      } */
        else if( !pub_file )
        {
            pub_file = argv[i];
        }
        else if( !prv_file )
        {
            prv_file = argv[i];
        }
        else if( !in_file )
        {
            in_file = argv[i];
        }
        else
            die(usage);

    if( !pub_file || !prv_file || !in_file )
        die(usage);

    if( !out_file )
    {
        if(  strlen(in_file) > 6 &&
                !strcmp(in_file + strlen(in_file) - 6, ".cpabe") )
            out_file = g_strndup(in_file, strlen(in_file) - 6);
        else
            out_file = strdup(in_file);
    }

    if( keep && !strcmp(in_file, out_file) )
        die("cannot keep input file when decrypting file in place (try -o)\n");
}

int
main( int argc, char** argv )
{
    FILE *fp;
    bswabe_pub_t* pub;
    bswabe_prv_t* prv;
    int i, file_len;
    GByteArray* aes_buf;
    GByteArray* plt;
    GByteArray* cph_buf;
    bswabe_cph_t* cph;
    element_t m;
    clock_t start, end;
    float time_result;
    static unsigned char buff_orig[34], buff_calc[34];

    parse_args(argc, argv);

    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
    prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);

    //Start timer
    start = clock();

    if ((fp = fopen(in_file, "rb")) != NULL)
    {
        fseek(fp, -64, SEEK_END);
        for (i = 0; i < 64; i += 2)
        {
            fscanf(fp, "%02x", (unsigned int *) &buff_orig[(i/2)]);
        }
        fclose(fp);
    } else {
        printf("Error reading HMAC256!\n");
        keep = 1;
    }

    read_cpabe_file(in_file, &cph_buf, &file_len, &aes_buf);

    cph = bswabe_cph_unserialize(pub, cph_buf, 1);
    if( !bswabe_dec(pub, prv, cph, m) )
        die("%s", bswabe_error());
    bswabe_cph_free(cph);

    plt = aes_128_cbc_decrypt(aes_buf, m);
    g_byte_array_set_size(plt, file_len);
    g_byte_array_free(aes_buf, 1);

    spit_file(out_file, plt, 1);

    //End Timer, display output
    end = clock();
    time_result = (float) (end-start)/(float) CLOCKS_PER_SEC;
    printf("Computation took %f seconds\n",time_result);

    if (_gcry_hmac256_file(buff_calc, 32, out_file, hmac_key, strlen(hmac_key)) != -1)
    {
        printf((!memcmp(buff_orig, buff_calc, 32)) ? "HMAC256 is valid!\n" : "Error: Invalid HMAC256!\n");
    }

    if( !keep )
        unlink(in_file);

    /* report ops if necessary */
/*  if( report_ops ) */
/*      printf("pairings:        %5d\n" */
/*                   "exponentiations: %5d\n" */
/*                   "multiplications: %5d\n", num_pairings, num_exps, num_muls); */

    return 0;
}
