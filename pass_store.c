#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "pass_store.h"

#define SALT_LEN 8

// Every 3 bytes of salt encoded as 4 characters + possible padding
#define SALT_LEN_BASE64 (SALT_LEN/3 + 1) * 4
#define SHA512_DIGEST_LENGTH_BASE64 (SHA512_DIGEST_LENGTH/3 + 1) * 4

#define MAX_USER_LEN 32
#define PASS_FILE_PATH "passwords"

typedef struct user_pass_s {
  // NULL-terminated username string
  // if username is empty, consider the entry removed
  char username[MAX_USER_LEN];
  // binary password hash (no encoding)
  uint8_t pass_hash[SHA512_DIGEST_LENGTH];
  // NULL-terminated Base64 encoded salt string
  char salt[SALT_LEN_BASE64+1];
} user_pass_t;


static int __pass_store_load(user_pass_t **passwords_out, size_t *num_pass_out)
{
    FILE* passFile = fopen(PASS_FILE_PATH, "r");
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t index = 0;

    if (passFile == NULL)
        return 1;

    while ((read = getline(&line, &len, passFile)) != -1) {
      uint8_t pass_hash[SHA512_DIGEST_LENGTH];
      char username[MAX_USER_LEN];
      char salt_b64[SALT_LEN_BASE64];

      char* token = strtok(line, ":");
      //username = token;
      strcpy(username, token);
      strcpy(passwords_out[index]->username, username);

      token = strtok(NULL, "$");
      char* hash_type = token;
      token = strtok(NULL, "$");
      //salt_b64 = token;
      strcpy(salt_b64, token);
      strcpy(passwords_out[index]->salt, username);

      token = strtok(NULL, "$");
      char* hash_b64 = token;


      BIO *enc_bio = BIO_new_mem_buf(hash_b64, strlen(hash_b64));
      BIO *b64_bio = BIO_new(BIO_f_base64());
      BIO_push(b64_bio, enc_bio);
      BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
      int num_read = BIO_read(b64_bio, pass_hash, SHA512_DIGEST_LENGTH);
      (void)num_read;

      strcpy(passwords_out[index]->pass_hash, pass_hash);


      BIO_free_all(b64_bio);
      index++;
    }
      *num_pass_out = index;

    fclose(passFile);
    if (line)
        free(line);

  return 0;
}


static int __pass_store_save(user_pass_t *passwords, size_t num_pass, int append)
{
  
  FILE* passFile;

  if (append)
  {
    passFile = fopen(PASS_FILE_PATH, "a");
  }
  else
  {
    passFile = fopen(PASS_FILE_PATH, "w");
  }
  
  for (int i = 0; i < num_pass; i++)
  {
    user_pass_t currentUser = passwords[i];
    char* hash_ptr = NULL;
    long hash_b64_len;


    BIO* b64_bio = BIO_new(BIO_f_base64());
    BIO *enc_bio = BIO_new(BIO_s_mem());
    BIO_push(b64_bio, enc_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64_bio, currentUser.pass_hash, SHA512_DIGEST_LENGTH);
    BIO_flush(b64_bio);
    hash_b64_len = BIO_get_mem_data(enc_bio, &hash_ptr);

    char hash_b64[hash_b64_len];
    strcpy(hash_b64, hash_ptr);
    BIO_free_all(b64_bio);


    fwrite(currentUser.username, sizeof(char), strlen(currentUser.username), passFile);
    fwrite(":$6$", sizeof(char), 4, passFile);
    fwrite(currentUser.salt, sizeof(char), SALT_LEN_BASE64, passFile);
    fwrite("$", sizeof(char), 1, passFile);
    fwrite(hash_b64, sizeof(char), hash_b64_len, passFile);
    fwrite("\n", sizeof(char), 1, passFile);

  }

  fclose(passFile);
  return 0;
}


/*
 * pass_store_add_user - adds a new user to the password store
 *
 * @username: NULL-delimited username string
 * @password: NULL-delimited password string
 *
 * Returns 0 on success, -1 on failure
 */
int pass_store_add_user(const char *username, const char *password)
{
  user_pass_t new_user;
  uint8_t salt[SALT_LEN];
  char* salt_ptr = NULL;
  char salt_b64[SALT_LEN_BASE64+1];
  long salt_b64_len;
  unsigned char salted_password[SALT_LEN_BASE64 + strlen(password)];
  uint8_t pass_hash[SHA512_DIGEST_LENGTH];

  //generate a random salt
  RAND_bytes(salt, SALT_LEN);


  BIO* b64_bio = BIO_new(BIO_f_base64());
  BIO *enc_bio = BIO_new(BIO_s_mem());
  BIO_push(b64_bio, enc_bio);
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64_bio, salt, SALT_LEN); //write the salt to the BIO
  BIO_flush(b64_bio);
  //set salt_ptr to point at enc_bio and set salt_b64_len tothe length of enc_bio
  salt_b64_len = BIO_get_mem_data(enc_bio, &salt_ptr);  

  //grab the salt and put it into a proper string
  strcpy(salt_b64, salt_ptr);
  salt_b64[SALT_LEN_BASE64] = '\0'; //add nul terminating char

  BIO_free_all(b64_bio);

  (void)salt_b64_len;
  //unsigned char *SHA512(const unsigned char *d, size_t n,
  //    unsigned char *md);

  //put the salt and the password together
  strcpy(salted_password, salt_b64);
  strcpy(salted_password + SALT_LEN_BASE64, password);

  //hash the salt and password together
  SHA512(salted_password, SALT_LEN_BASE64 + strlen(password), pass_hash);


  strcpy(new_user.username, username);
  strcpy(new_user.salt, salt_b64);
  strcpy(new_user.pass_hash, pass_hash);

  __pass_store_save(&new_user, 1, 1);
  return 0;
}


/* 
 * pass_store_remove_user - removes a user from the password store
 *
 * @username: NULL-delimited username string
 *
 * Returns 0 on success, -1 on failure
 */
int pass_store_remove_user(const char *username)
{
  FILE* passFile;
  FILE* newPassFile;

  char* line = NULL;
  char* user;
  size_t len = 0;
  ssize_t read;
  int success = 0;

  passFile = fopen(PASS_FILE_PATH, "r");
  newPassFile = fopen("tempPasswords", "w");

  while ((read = getline(&line, &len, passFile)) != -1) {
    char lineCpy[len];
    strcpy(lineCpy, line);
    user = strtok(lineCpy, ":");
    //if the username is not the same, put that line into the new file
    if(strcmp(user, username)){
      fprintf(newPassFile, "%s", line);
    }
    else{//username was found
      success=1;
    }
  }

  //close the file pointers
  fclose(newPassFile);
  fclose(passFile);
  //delete the old password file
  remove(PASS_FILE_PATH);
  //rename the new password file to the old password file
  rename("tempPasswords", PASS_FILE_PATH);
  
  if(success){ //we found and removed the entry
    return 0;
  }
  //we couldnt find the entry
  return -1;
}


/*
 * pass_store_check_password - check the password of a user
 *
 * @username: NULL-delimited username string
 * @passwrod: NULL-delimited password string
 *
 * Returns 0 on success, -1 on failure
 */
int pass_store_check_password(const char *username, const char *password)
{
  /*user_pass_t* users[MAX_USER_LEN];
  for (int i = 0; i < MAX_USER_LEN; i++)
  {
    users[i] = (user_pass_t*)malloc(sizeof(user_pass_t));
  }
  size_t num_users;
  __pass_store_load(users, &num_users);


  for (int i = 0; i < num_users; i++)
  {
    fprintf(stderr, "usr: %s, salt_b64: %s\n", users[i]->username, users[i]->salt);
  }


  for (int i = 0; i < MAX_USER_LEN; i++)
  {
    free(users[i]);
  }
  return 0;*/

  FILE* passFile;

  char* line = NULL;
  char* user;
  size_t len = 0;
  ssize_t read;
  int success = 0;

  char* salt_b64;
  char* user_pass;
  unsigned char salted_password[SALT_LEN_BASE64 + strlen(password)];
  uint8_t pass_hash[SHA512_DIGEST_LENGTH];
  long hash_b64_len;
  char* hash_ptr = NULL;

  passFile = fopen(PASS_FILE_PATH, "r");

  while ((read = getline(&line, &len, passFile)) != -1) {
    char lineCpy[len];
    strcpy(lineCpy, line);
    //strtok is destructive so we have to make a copy of the string
    user = strtok(lineCpy, ":");
    //if the username is the same, break so we can check the password
    if(!strcmp(user, username)){
      //mark that we actually found the right user
      success = 1;
      break;
    }
  }
  //if we cant find the user, fail
  if(!success){
    return -1;
  }

  //first string before a $ is useless
  strtok(line, "$");
  //second is the hash alg
  strtok(NULL, "$");
  //third is salt
  salt_b64 = strtok(NULL, "$");
  //fourth is the hashed pass
  user_pass = strtok(NULL, "$");

  //put the salt and the password together
  strcpy(salted_password, salt_b64);
  strcpy(salted_password + SALT_LEN_BASE64, password);

  //hash the salt and password together
  SHA512(salted_password, SALT_LEN_BASE64 + strlen(password), pass_hash);

  //essentially decode the pass_hash into a readable string
  BIO* b64_bio = BIO_new(BIO_f_base64());
  BIO *enc_bio = BIO_new(BIO_s_mem());
  BIO_push(b64_bio, enc_bio);
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64_bio, pass_hash, SHA512_DIGEST_LENGTH);
  BIO_flush(b64_bio);
  hash_b64_len = BIO_get_mem_data(enc_bio, &hash_ptr);
  
  char hash_b64[hash_b64_len];
  strcpy(hash_b64, hash_ptr);
  BIO_free_all(b64_bio);

  //need to append a newline char to the end so things actually match up
  strncat(hash_b64, "\n", hash_b64_len);

  //if they match, succeed
  if(!strcmp(user_pass, hash_b64)){
    return 0;
  }
  //else fail
  return -1;
}

