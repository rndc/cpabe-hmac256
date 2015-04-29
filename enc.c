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

hmac256_context_t hd;
const unsigned char *digest;


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
write_hmac256()
{
    FILE *fp;
    int i, retval;
    size_t n, keylen, dlen;
    char buffer[4096];

    retval = -1;
    if (!(fp = fopen(in_file, "rb")))
    {
        printf("Can't open input file!\n");
        goto done;
    }

    keylen = strlen(hmac_key);
    if (!(hd = _gcry_hmac256_new(hmac_key, keylen)))
    {
        printf("Can't allocate context!\n");
        goto done;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), fp)))
    {
        _gcry_hmac256_update(hd, buffer, n);
    }

    fclose(fp);
    digest = _gcry_hmac256_finalize (hd, &dlen);
    if (!digest)
    {
        printf("Error computing HMAC!\n");
        goto done;
    }

    fp = fopen(out_file, "a+");
    if (fp != NULL)
    {
        for (i = 0; i < dlen; i++)
        {
            fprintf(fp, "%02x", digest[i]);
        }
        retval = 0;
    }
    _gcry_hmac256_release (hd);

done:
    if (fp) { fclose(fp); }
    return retval;
}

int
main(int argc, char** argv)
{
    bswabe_pub_t* pub;
    bswabe_cph_t* cph;
    int file_len;
    GByteArray* plt;
    GByteArray* cph_buf;
    GByteArray* aes_buf;
    element_t m;

    clock_t start, end;
    float time_result;

    parse_args(argc, argv);

    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

    //Start timer
    start = clock();
    if (!(cph = bswabe_enc(pub, m, policy)))
        die("%s", bswabe_error());
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

    if (!write_hmac256())
        printf("HMAC function done!\n");

    if (!keep)
        unlink(in_file);

    return 0;
}
