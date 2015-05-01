#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <time.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"
#include "hmac256.h"

char* usage =
    "Usage: cpabe-enc [OPTION ...] PUB_KEY FILE [POLICY]\n"
    "\n"
    "Encrypt FILE under the decryption policy POLICY using public key\n"
    "PUB_KEY. The encrypted file will be written to FILE.cpabe unless\n"
    "the -o option is used. The original file will be removed. If POLICY\n"
    "is not specified, the policy will be read from stdin.\n"
    "\n"
    "Mandatory arguments to long options are mandatory for short options too.\n\n"
    " -h, --help               print this message\n\n"
    " -v, --version            print version information\n\n"
    " -k, --keep-input-file    don't delete original file\n\n"
    " -o, --output FILE        write resulting key to FILE\n\n"
    " -y, --key KEY            hmac256 key\n\n"
    " -d, --deterministic      use deterministic \"random\" numbers\n"
    "                          (only for debugging)\n\n"
    "";

char* pub_file = 0;
char* in_file  = 0;
char* out_file = 0;
char* hmac_key = 0;
char* policy   = 0;
int   keep     = 0;

void
parse_args(int argc, char** argv)
{
    int i;

    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            printf("%s", usage);
            exit(0);
        }
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version"))
        {
            printf(CPABE_VERSION, "-enc");
            exit(0);
        }
        else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file"))
        {
            keep = 1;
        }
        else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output"))
        {
            if (++i >= argc)
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
        else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic"))
        {
            pbc_random_set_deterministic(0);
        }
        else if (!pub_file)
        {
            pub_file = argv[i];
        }
        else if (!in_file)
        {
            in_file = argv[i];
        }
        else if (!policy)
        {
            policy = parse_policy_lang(argv[i]);
        }
        else
            die(usage);
    }

    if (!pub_file || !in_file || !hmac_key)
        die(usage);

    if (!out_file)
        out_file = g_strdup_printf("%s.cpabe", in_file);

    if (!policy)
        policy = parse_policy_lang(suck_stdin());
}


int
main(int argc, char** argv)
{
    FILE *fp;
    bswabe_pub_t* pub;
    bswabe_cph_t* cph;
    GByteArray* plt;
    GByteArray* cph_buf;
    GByteArray* aes_buf;
    element_t m;
    int i, file_len;
    clock_t start, end;
    float time_result;
    static unsigned char buff[34];

    parse_args(argc, argv);

    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

    //Start timer
    start = clock();
    if (!(cph = bswabe_enc(pub, m, policy)))
    {
        die("%s", bswabe_error());
    }
    free(policy);

    cph_buf = bswabe_cph_serialize(cph);
    bswabe_cph_free(cph);

    plt = suck_file(in_file);
    file_len = plt->len;
    aes_buf = aes_128_cbc_encrypt(plt, m);
    g_byte_array_free(plt, 1);
    element_clear(m);

    write_cpabe_file(out_file, cph_buf, file_len, aes_buf);
    //End Timer, display output
    end = clock();
    time_result = (float) (end - start) / (float) CLOCKS_PER_SEC;
    printf("Computation took %f seconds\n", time_result);

    g_byte_array_free(cph_buf, 1);
    g_byte_array_free(aes_buf, 1);

    if (_gcry_hmac256_file(buff, 32, in_file, hmac_key, strlen(hmac_key)) != -1)
    {
        if ((fp = fopen(out_file, "a+")) != NULL)
        {
            for (i = 0; i < 32; i++)
            {
                fprintf(fp, "%02x", buff[i]);
            }
            fclose(fp);
            printf("Added HMAC256!\n");
        } else {
            printf("Error: HMAC256 function failed!\n");
            keep = 1;
        }
    }

    if (!keep)
        unlink(in_file);

    return 0;
}
