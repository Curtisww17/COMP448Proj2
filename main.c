#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "pass_store.h"


static void print_usage_exit(const char *prog)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s add-user <username>\n", prog);
  fprintf(stderr, "  %s remove-user <username>\n", prog);
  fprintf(stderr, "  %s check-password <username>\n", prog);
  exit(0);
}


static int query_password(const char *username, char *password, size_t password_size, int verify)
{
  size_t pass_size = password_size;
  char *pass1 = malloc(pass_size);
  struct termios old, new;

  tcgetattr(0, &old);
  memcpy(&new, &old, sizeof(struct termios));
  new.c_lflag &= ~ECHO;
  tcsetattr(0, TCSAFLUSH, &new);

  fprintf(stdout, "Enter password for user '%s': ", username);
  getline(&pass1, &pass_size, stdin);
  fprintf(stdout, "\n");

  if (verify) {
    pass_size = password_size;
    char *pass2 = malloc(pass_size);
    fprintf(stdout, "Re-enter password: ");
    getline(&pass2, &pass_size, stdin);
    fprintf(stdout, "\n");

    tcsetattr(0, TCSAFLUSH, &old);

    if (strlen(pass1) != strlen(pass2) ||
        strncmp(pass1, pass2, strlen(pass1)) != 0) {
      fprintf(stderr, "Passwords do not match!\n");
      free(pass1);
      free(pass2);
      return -1;
    }
  }

  tcsetattr(0, TCSAFLUSH, &old);

  strncpy(password, pass1, password_size-1);
  free(pass1);

  return 0;
}


int main (int argc, char *argv[])
{
  char password[64];

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // 1. parse command line arguments and execute desired command
  if (argc < 2) {
    fprintf(stderr, "Must specify a command to run!\n");
    print_usage_exit(argv[0]);
  }

  int res = -1;
  if (strcmp(argv[1], "add-user") == 0) {
    // add a new user to the user store
    if (argc != 3) {
      fprintf(stderr, "Command '%s' takes exactly 1 argument!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    memset(password, 0, sizeof(password));
    if (query_password(argv[2], password, sizeof(password), 1) != 0)
      fprintf(stderr, "Unable to get user password\n");
    else
      res = pass_store_add_user(argv[2], password);
  }
  else if (strcmp(argv[1], "remove-user") == 0) {
    // remove a user from the password store
    if (argc != 3) {
      fprintf(stderr, "Command '%s' takes exactly 1 argument!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    res = pass_store_remove_user(argv[2]);
  }
  else if (strcmp(argv[1], "check-password") == 0) {
    // check the password for a user in the user store
    if (argc != 3) {
      fprintf(stderr, "Command '%s' takes exactly 1 argument!\n", argv[1]);
      print_usage_exit(argv[0]);
    }

    memset(password, 0, sizeof(password));
    if (query_password(argv[2], password, sizeof(password), 0) != 0)
      fprintf(stderr, "Unable to get user password\n");
    else
      res = pass_store_check_password(argv[2], password);
  }
  else {
    fprintf(stderr, "Invalid command: %s\n", argv[1]);
    print_usage_exit(argv[0]);
  }

  if (res == 0)
    fprintf(stderr, "Command '%s' successful.\n", argv[1]);
  else
    fprintf(stderr, "Command '%s' failed!\n", argv[1]);

  ERR_free_strings();
  EVP_cleanup();

  return 0; 
}

