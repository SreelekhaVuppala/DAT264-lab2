/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
 #include "pwent.h" 


#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define PASSWORD_AGE_LIMIT 10
#define MAX_FAILED_ATTEMPTS 5

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	signal(SIGINT, SIG_IGN);  // Ignore Ctrl+C
    signal(SIGTSTP, SIG_IGN); // Ignore Ctrl+Z
    signal(SIGQUIT, SIG_IGN); // (SIGQUIT)
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

/* Replace gets() with fgets() */
if (fgets(user, sizeof(user), stdin) == NULL) {
	printf("Error reading input.\n");
	exit(0);
}

/* Remove the newline character that fgets() may leave at the end of the string */
user[strcspn(user, "\n")] = '\0';

		// if (gets(user) == NULL) /* gets() is vulnerable to buffer */
		// 	exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			if (passwddata->pwfailed >= MAX_FAILED_ATTEMPTS) {
                printf("Account locked due to too many failed attempts.\n");
            } 
			else if (strcmp(crypt(user_pass, passwddata->passwd_salt), passwddata->passwd) == 0) {
                printf("You're in! Failed attempts: %d\n", passwddata->pwfailed);
                passwddata->pwfailed = 0;
                passwddata->pwage++;
                if (passwddata->pwage > PASSWORD_AGE_LIMIT) {
                    printf("Warning: Please change your password.\n");
                }
				mysetpwent(user, passwddata);

				// Set user ID and start shell
				int ret = setuid(passwddata->uid);
				if(ret == 0){
				execl("/bin/sh", "sh", NULL);
				perror("execl failed");
				exit(EXIT_FAILURE);
				} else {
					printf("Incorrect user ID\n");
					exit(0);
				}
            } else {
                passwddata->pwfailed++;
                printf("Login Incorrect. Failed attempts: %d\n", passwddata->pwfailed);
            }
			mysetpwent(user, passwddata);
		}
		else printf("Login Incorrect \n");
	}
	return 0;
}
