#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <argp.h>

#include "oidc-token.h"
#include "api.h"
#include "oidc_utilities.h"
#include "version.h"


const char *argp_program_version = TOKEN_VERSION;

const char *argp_program_bug_address = BUG_ADDRESS;

/* This structure is used by main to communicate with parse_opt. */
struct arguments {
  char* args[1];            /* account shortname */
  int list_accounts;
  unsigned long min_valid_period;  /* Arguments for -t */
};

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
   */
static struct argp_option options[] = {
  {"listaccounts", 'l', 0, 0, "Lists the currently loaded accounts", 0},
  {"time",  't', "min_valid_period", 0, "period of how long the access token should be at least valid in seconds", 0},
  {0}
};

/*
   PARSER. Field 2 in ARGP.
   Order of parameters: KEY, ARG, STATE.
   */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key)
  {
    case 'l':
      arguments->list_accounts = 1;
      break;
    case 't':
      if(!isdigit(*arg)) {
        return ARGP_ERR_UNKNOWN;
      }
      arguments->min_valid_period = atoi(arg);
      break;
    case ARGP_KEY_ARG:
      if(state->arg_num >= 1) {
        argp_usage(state);
      }
      arguments->args[state->arg_num] = arg;
      break;
    case ARGP_KEY_END:
      if(arguments->list_accounts) {
        break;
      }
      if (state->arg_num < 1) {
        argp_usage (state);
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/*
   ARGS_DOC. Field 3 in ARGP.
   A description of the non-option command-line arguments
   that we accept.
   */
static char args_doc[] = "ACCOUNT_SHORTNAME | -l";

/*
   DOC.  Field 4 in ARGP.
   Program documentation.
   */
static char doc[] = "oidc-token -- A client for oidc-agent for getting OIDC access tokens.";

/*
   The ARGP structure itself.
   */
static struct argp argp = {options, parse_opt, args_doc, doc};



int main (int argc, char **argv) {
  struct arguments arguments;

  /* Set argument defaults */
  arguments.min_valid_period = 0;
  arguments.list_accounts = 0;
  arguments.args[0]=NULL;
  /* parse arguments */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);


  if(arguments.list_accounts) {
    char* accountList = getLoadedAccounts(); // for a list of loaded accounts, simply call the api
    if(accountList==NULL) {
      fprintf(stderr, "Error: %s\n", oidc_serror());
    } else {
      printf("The following accounts are loaded: %s\n", accountList);
      clearFreeString(accountList);
    }
  }
  if(arguments.args[0]) {
    char* access_token = getAccessToken(arguments.args[0], arguments.min_valid_period); // for getting an valid access token just call the api
    if(access_token==NULL) {
      fprintf(stderr, "Error: %s\n", oidc_serror());
    } else {
      printf("%s\n", access_token);
      clearFreeString(access_token);
    }
  }
  return 0;
}
