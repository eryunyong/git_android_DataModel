/*
 * cli - Command Line Interface for the Unified Configuration Interface
 * Copyright (C) 2008 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include "uci.h"
#include <dirent.h> 

#define MAX_ARGS	4 /* max command line arguments for batch mode */

static const char *appname;
static enum {
	CLI_FLAG_MERGE =    (1 << 0),
	CLI_FLAG_QUIET =    (1 << 1),
        CLI_FLAG_NOCOMMIT = (1 << 2),
        CLI_FLAG_BATCH =    (1 << 3),
} flags;

static FILE *input;

static struct uci_context *ctx;
enum {
	/* section cmds */
	CMD_GET,
	CMD_SET,
	CMD_DEL,
	CMD_RENAME,
	CMD_REVERT,
	/* package cmds */
	CMD_SHOW,
	CMD_CHANGES,
	CMD_EXPORT,
	CMD_COMMIT,
	/* other cmds */
	CMD_ADD,
	CMD_IMPORT,
	CMD_HELP,
};

static int uci_cmd(int argc, char **argv);

static void uci_usage(void)
{
	fprintf(stderr,
			"Usage: %s [<options>] <command> [<arguments>]\n\n"
			"Commands:\n"
			"\tbatch\n"
			"\texport     [<config>]\n"
			"\timport     [<config>]\n"
			"\tchanges    [<config>]\n"
			"\tcommit     [<config>]\n"
			"\tadd        <config> <section-type>\n"
			"\tdel        <config>.<section>.<option>\n"
			"\tshow       [<config>[.<section>[.<option>]]]\n"
			"\tget        <config>.<section>[.<option>]\n"
			"\tset        <config>.<section>[.<option>]=<value>\n"
			"\trename     <config>.<section>[.<option>]=<name>\n"
			"\trevert     <config>[.<section>[.<option>]]\n"
			"\n"
			"Options:\n"
			"\t-f <file>  use <file> as input instead of stdin\n"
			"\t-m         when importing, merge data into an existing package\n"
			"\t-n         name unnamed sections on export (default)\n"
			"\t-N         don't name unnamed sections\n"
			"\t-p <path>  add a search path for config change files\n"
			"\t-P <path>  add a search path for config change files and use as default\n"
			"\t-q         quiet mode (don't print error messages)\n"
			"\t-s         force strict mode (stop on parser errors, default)\n"
			"\t-S         disable strict mode\n"
			"\n",
		appname
                );
}

static void cli_perror(void)
{
	if (flags & CLI_FLAG_QUIET)
		return;

	uci_perror(ctx, appname);
}

static void uci_show_section(struct uci_section *p)
{
	struct uci_element *e;
	const char *cname, *sname;

	cname = p->package->e.name;
	sname = p->e.name;
	printf("%s.%s=%s\n", cname, sname, p->type);
	uci_foreach_element(&p->options, e) {
		printf("%s.%s.%s=%s\n", cname, sname, e->name, uci_to_option(e)->value);
	}
}

static void uci_show_package(struct uci_package *p)
{
	struct uci_element *e;

	uci_foreach_element( &p->sections, e) {
		uci_show_section(uci_to_section(e));
	}
}

static void uci_show_changes(struct uci_package *p)
{
	struct uci_element *e;

	uci_foreach_element(&p->saved_history, e) {
		struct uci_history *h = uci_to_history(e);

		if (h->cmd == UCI_CMD_REMOVE)
			printf("-");
		printf("%s.%s", p->e.name, h->section);
		if (e->name)
			printf(".%s", e->name);
		if (h->cmd != UCI_CMD_REMOVE)
			printf("=%s", h->value);
		printf("\n");
	}
}

static int package_check(const char *package)
{
	if (-1 == access(package, R_OK | W_OK))
	{
		FILE *fp = fopen(package, "w+");
		if (NULL == fp)
			return -1;
		fclose(fp);
	}
	return 0;
}

static int section_check(struct uci_list *list, const char *section)
{
	struct uci_element *e;
	uci_foreach_element(list, e)
	{
		if (!strcmp(e->name, section))
			return 0;
	}
	return -1;
}



static int package_cmd(int cmd, char *package)
{
	struct uci_package *p = NULL;
	int ret;
	char name[256] = {0};

	if (cmd == CMD_CHANGES)
		ctx->flags |= UCI_FLAG_SAVED_HISTORY;

	if ((cmd == CMD_EXPORT) || (cmd == CMD_SHOW))
	{
		ret = load_merge_uci(ctx, package, &p);
	}
	else
	{
		ret = uci_load(ctx, package, &p);
	}

	if (cmd == CMD_CHANGES)
		ctx->flags &= ~UCI_FLAG_SAVED_HISTORY;

	if (ret != UCI_OK) {
		cli_perror();
		return 1;
	}
	if (!p)
		return 0;
	switch(cmd) {
	case CMD_CHANGES:
		uci_show_changes(p);
		break;
	case CMD_COMMIT:
		if (flags & CLI_FLAG_NOCOMMIT)
			return 0;
		if (uci_commit(ctx, &p, false) != UCI_OK)
			cli_perror();
		snprintf(name, sizeof(name)-1, "%s/%s", UCI_SAVEDIR, package);
		unlink(name);
		break;
	case CMD_EXPORT:
		uci_export(ctx, stdout, p, true);
		break;
	case CMD_SHOW:
		uci_show_package(p);
		break;
	}

	uci_unload(ctx, p);
	return 0;
}

static int uci_do_import(int argc, char **argv)
{
	struct uci_package *package = NULL;
	char *name = NULL;
	int ret = UCI_OK;
	bool merge = false;

	if (argc > 2)
		return 255;

	if (argc == 2)
		name = argv[1];
	else if (flags & CLI_FLAG_MERGE)
		/* need a package to merge */
		return 255;

	if (flags & CLI_FLAG_MERGE) {
		if (uci_load(ctx, name, &package) != UCI_OK)
			package = NULL;
		else
			merge = true;
	}
	ret = uci_import(ctx, input, name, &package, (name != NULL));
	if (ret == UCI_OK) {
		if (merge) {
			ret = uci_save(ctx, package);
		} else {
			struct uci_element *e;
			/* loop through all config sections and overwrite existing data */
			uci_foreach_element(&ctx->root, e) {
				struct uci_package *p = uci_to_package(e);
				ret = uci_commit(ctx, &p, true);
			}
		}
	}

	if (ret != UCI_OK) {
		cli_perror();
		return 1;
	}

	return 0;
}

static int uci_do_package_cmd(int cmd, int argc, char **argv)
{
	char **configs = NULL;
	char **p;
	int ret = 0;
	struct dirent *dent = NULL;
	char dir[256] = UCI_SAVEDIR;
	DIR *dd = NULL;

	if (argc > 2)
		return 255;

	if ( argc == 1 ) {
		dd = opendir(dir);
		if ( dd == NULL ) {
			cli_perror();
			return 1;
		}
		while ( (dent = readdir(dd)) != NULL ) {
			if (dent->d_ino == 0) {
				continue;
			}
			if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
				continue;
			}
			ret |= package_cmd(cmd, dent->d_name);
		}
		closedir(dd);
		return ret;
	}

	if (argc == 2)
		return package_cmd(cmd, argv[1]);

	if ((uci_list_configs(ctx, &configs) != UCI_OK) || !configs) {
		cli_perror();
		return 1;
	}

	for (p = configs; *p; p++) {
		package_cmd(cmd, *p);
	}

	return 0;
}
static int uci_do_add(int argc, char **argv)
{
	struct uci_package *p = NULL;
	struct uci_section *s = NULL;
	int ret;

	if (argc != 3)
		return 255;

	/* when doing uci add, if package doesn't exist, create it */

	char name[256] = {0};

	if ((argv[1][0] != '/') && (argv[1][0] != '.'))
	{
		sprintf(name, "%s/%s", ctx->confdir, argv[1]);
	}
	else
	{
		sprintf(name, "%s", argv[1]);
	}

	if (-1 == package_check(name))
		return -1;

	ret = uci_load(ctx, argv[1], &p);
	if (ret != UCI_OK)
		goto done;

	ret = uci_add_section(ctx, p, argv[2], &s);
	if (ret != UCI_OK)
		goto done;

	ret = uci_save(ctx, p);

done:
	if (ret != UCI_OK)
		cli_perror();
	else if (s)
		fprintf(stdout, "%s\n", s->e.name);

	return ret;
}

static int uci_do_section_cmd(struct uci_context *ctx, int cmd, char * tag, char * buffer, int length)
{
	struct uci_package *p = NULL;
	struct uci_element *e = NULL;
	char *package = NULL;
	char *section = NULL;
	char *option = NULL;
	char *value = NULL;
	char **ptr = NULL;
	int ret = UCI_OK;

	char name[256] = {0};

	switch(cmd) {
	case CMD_SET:
	case CMD_RENAME:
		ptr = &value;
		break;
	default:
		break;
	}

	if (uci_parse_tuple(ctx, tag, &package, &section, &option, ptr) != UCI_OK)
		return 1;

	if (section && !section[0])
		return 1;

	/* when doing uci set, if package doesn't exist, create it */
	if (cmd == CMD_SET)
	{
		if ((package[0] != '/') && (package[0] != '.'))
		{
			sprintf(name, "%s/%s", ctx->confdir, package);
		}
		else
		{
			sprintf(name, "%s", package);
		}

		if (-1 == package_check(name))
			return -1;

		if (load_merge_uci(ctx, package, &p) != UCI_OK)
		{
			cli_perror();
			return 1;
		}
		/* when doing uci set, if section doesn't exist, create it */
		if (-1 == section_check(&p->sections, section))
		{
			FILE *fp;

			char name_base[256] = {0};
			char sectiontype[256] = {0};
			char *packname = NULL;
			//add by james.xu 
			//��Ң����ģ�����config����ʱ��config������ֱ��д�����յ������ļ���
			//������tmp�£������û�ȡ�����޷�������ͬ��������
			char name_save[256] = {0};
			struct stat statbuf;
			//end add
			packname = strrchr(name, '/');

			/* get a section type */
			{  
				sprintf(name_base, "%s/%s", ctx->basedir, packname+1);

				sprintf(name_save, "%s/%s", ctx->savedir, packname+1);
				if (stat(ctx->savedir, &statbuf) < 0)
					mkdir(ctx->savedir, UCI_DIRMODE);

				uci_free_content(ctx);

				if (uci_load(ctx, name_base, &p) != UCI_OK)
				{
					cli_perror();
					return 1;
				}

				if (uci_lookup(ctx, &e, p, section, NULL) == UCI_OK)
				{
					if (e->type == UCI_TYPE_SECTION)
					{
						memset(sectiontype, 0, 256);
						strcpy(sectiontype, uci_to_section(e)->type);
					}
				}
			}

			if (sectiontype[0] == '\0')
			{       
				memset(sectiontype, 0, 256);
				strcpy(sectiontype, packname+1);
			}

			//modified by james.xu
			if((package[0] != '/') && (package[0] != '.'))
			{
				//����ļ��Ƿ����
				if(package_check(name_save) == -1)
				{
					return -1;
				}
				if (NULL == (fp = fopen(name_save, "a")))
				{
					return -1;
				}
			}
			else
			{
				if (NULL == (fp = fopen(name, "a")))
				{
					return -1;
				}
			}
			//end

			//modified by james.xu
			if((package[0] != '/') && (package[0] != '.'))
			{
				snprintf(buffer, 256, "%s.%s=%s\n", package, section, sectiontype);
			}
			else
			{
				snprintf(buffer, 256, "config %s %s\n", sectiontype, section);
			}
			//end


			fwrite(buffer, strlen(buffer), 1, fp);
			fclose(fp);

			uci_free_content(ctx);

			if (uci_load(ctx, package, &p) != UCI_OK)
			{
				cli_perror();
				return 1;
			}
		}
        else 
        {
            if(uci_check_change(ctx, p, section, option, value, NULL) == 0)
                return 0;
            else
            {
                uci_free_content(ctx);

                if (uci_load(ctx, package, &p) != UCI_OK)
                {
                    cli_perror();
                    return 1;
                }

                if (-1 == section_check(&p->sections, section))
                {
                    FILE *fp;

                    char name_base[256] = {0};
                    char sectiontype[256] = {0};
                    char *packname = NULL;
                    //add by james.xu 
                    //��Ң����ģ�����config����ʱ��config������ֱ��д�����յ������ļ���
                    //������tmp�£������û�ȡ�����޷�������ͬ��������
                    char name_save[256] = {0};
                    struct stat statbuf;
                    //end add
                    packname = strrchr(name, '/');

                    //get a section type
                    {  
                        sprintf(name_base, "%s/%s", ctx->basedir, packname+1);

                        sprintf(name_save, "%s/%s", ctx->savedir, packname+1);
                        if (stat(ctx->savedir, &statbuf) < 0)
                            mkdir(ctx->savedir, UCI_DIRMODE);

                        uci_free_content(ctx);

                        if (uci_load(ctx, name_base, &p) != UCI_OK)
                        {
                            cli_perror();
                            return 1;
                        }

                        if (uci_lookup(ctx, &e, p, section, NULL) == UCI_OK)
                        {
                            if (e->type == UCI_TYPE_SECTION)
                            {
                                memset(sectiontype, 0, 256);
                                strcpy(sectiontype, uci_to_section(e)->type);
                            }
                        }
                    }

                    if (sectiontype[0] == '\0')
                    {       
                        memset(sectiontype, 0, 256);
                        strcpy(sectiontype, packname+1);
                    }

                    //modified by james.xu
                    if((package[0] != '/') && (package[0] != '.'))
                    {
                        //����ļ��Ƿ����
                        if(package_check(name_save) == -1)
                        {
                            return -1;
                        }
                        if (NULL == (fp = fopen(name_save, "a")))
                        {
                            return -1;
                        }
                    }
                    else
                    {
                        if (NULL == (fp = fopen(name, "a")))
                        {
                            return -1;
                        }
                    }
                    //end

                    //modified by james.xu
                    if((package[0] != '/') && (package[0] != '.'))
                    {
                        snprintf(buffer, 256, "%s.%s=%s\n", package, section, sectiontype);
                    }
                    else
                    {
                        snprintf(buffer, 256, "config %s %s\n", sectiontype, section);
                    }
                    //end


                    fwrite(buffer, strlen(buffer), 1, fp);
                    fclose(fp);

                    uci_free_content(ctx);

                    if (uci_load(ctx, package, &p) != UCI_OK)
                    {
                        cli_perror();
                        return 1;
                    }
                }
            }
        }
	}
	else if (cmd == CMD_GET)
	{
		if (load_merge_uci(ctx, package, &p) != UCI_OK)
		{
			cli_perror();
			return 1;
		}
	}
	else
	{
		if (uci_load(ctx, package, &p) != UCI_OK)
		{
			cli_perror();
			return 1;
		}
	}

	if (!p)
		return 1;

	switch(cmd) {
	case CMD_GET:
		if (uci_lookup(ctx, &e, p, section, option) != UCI_OK)
			return 1;

		switch(e->type) {
		case UCI_TYPE_SECTION:
			value = uci_to_section(e)->type;
			break;
		case UCI_TYPE_OPTION:
			value = uci_to_option(e)->value;
			break;
		default:
			/* should not happen */
			return 1;
		}
		/* throw the value to stdout */
		printf("%s\n", value);
		break;
	case CMD_RENAME:
		ret = uci_rename(ctx, p, section, option, value);
		break;
	case CMD_REVERT:
		ret = uci_revert(ctx, &p, section, option);
		break;
	case CMD_SET:
		ret = uci_set(ctx, p, section, option, value, NULL);
		break;
	case CMD_DEL:
		ret = uci_delete(ctx, p, section, option);
		break;
	}

	/* no save necessary for get */
	if ((cmd == CMD_GET) || (cmd == CMD_REVERT))
		return 0;

	/* save changes, but don't commit them yet */
	if (ret == UCI_OK)
		ret = uci_save(ctx, p);

	/* Add by James.xu 2009.06.25  */
	if(ret == UCI_ERR_DUPLICATE && cmd == CMD_SET)
	{
		return 0;
	}
	/* End add by James */

	if (ret != UCI_OK) {
		cli_perror();
		return 1;
	}
	return 0;
}

static int uci_batch_cmd(void)
{
	char *argv[MAX_ARGS];
	char *str = NULL;
	int ret = 0;
	int i, j;

	for(i = 0; i <= MAX_ARGS; i++) {
		if (i == MAX_ARGS) {
			fprintf(stderr, "Too many arguments\n");
			return 1;
		}
		argv[i] = NULL;
		if ((ret = uci_parse_argument(ctx, input, &str, &argv[i])) != UCI_OK) {
			cli_perror();
			i = 0;
			break;
		}
		if (!argv[i][0])
			break;
		argv[i] = strdup(argv[i]);
		if (!argv[i]) {
			perror("uci");
			return 1;
		}
	}
	argv[i] = NULL;

	if (i > 0) {
		if (!strcasecmp(argv[0], "exit"))
			return 254;
		ret = uci_cmd(i, argv);
	} else
		return 0;

	for (j = 0; j < i; j++) {
		if (argv[j])
			free(argv[j]);
	}

	return ret;
}

static int uci_batch(void)
{
	int ret = 0;

	while (!feof(input)) {
		struct uci_element *e, *tmp;

		ret = uci_batch_cmd();
		if (ret == 254)
			return 0;
		else if (ret == 255)
			fprintf(stderr, "Unknown command\n");

		/* clean up */
		uci_foreach_element_safe(&ctx->root, tmp, e) {
			uci_unload(ctx, uci_to_package(e));
		}
	}
	return 0;
}

static int uci_cmd(int argc, char **argv)
{
	int cmd = 0;

	if (!strcasecmp(argv[0], "batch") && !(flags & CLI_FLAG_BATCH))
		return uci_batch();
	else if (!strcasecmp(argv[0], "show"))
		cmd = CMD_SHOW;
	else if (!strcasecmp(argv[0], "changes"))
		cmd = CMD_CHANGES;
	else if (!strcasecmp(argv[0], "export"))
		cmd = CMD_EXPORT;
	else if (!strcasecmp(argv[0], "commit"))
		cmd = CMD_COMMIT;
	else if (!strcasecmp(argv[0], "get"))
		cmd = CMD_GET;
	else if (!strcasecmp(argv[0], "set"))
		cmd = CMD_SET;
	else if (!strcasecmp(argv[0], "ren") ||
	         !strcasecmp(argv[0], "rename"))
		cmd = CMD_RENAME;
	else if (!strcasecmp(argv[0], "revert"))
		cmd = CMD_REVERT;
	else if (!strcasecmp(argv[0], "del"))
		cmd = CMD_DEL;
	else if (!strcasecmp(argv[0], "import"))
		cmd = CMD_IMPORT;
	else if (!strcasecmp(argv[0], "help"))
		cmd = CMD_HELP;
	else if (!strcasecmp(argv[0], "add"))
		cmd = CMD_ADD;
	else
		cmd = -1;

	switch(cmd) {
		case CMD_GET:
		case CMD_SET:
			{
				char buffer[256];
				return uci_do_section_cmd(ctx, cmd, argv[1], buffer, 255);
			}
		case CMD_DEL:
		case CMD_RENAME:
		case CMD_REVERT:
			{
				char buffer[256];
				return uci_do_section_cmd(ctx, cmd, argv[1], buffer, 255);
			}
		case CMD_SHOW:
		case CMD_EXPORT:
		case CMD_COMMIT:
		case CMD_CHANGES:
			return uci_do_package_cmd(cmd, argc, argv);
		case CMD_IMPORT:
			return uci_do_import(argc, argv);
		case CMD_ADD:
			return uci_do_add(argc, argv);
		case CMD_HELP:
			uci_usage();
			return 0;
		default:
			return 255;
	}
}

int main(int argc, char **argv)
{
	int ret;
	int c;

	flags |= CLI_FLAG_QUIET;
	appname = argv[0];
	input = stdin;
	ctx = uci_alloc_context();
	if (!ctx) {
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	while((c = getopt(argc, argv, "f:mnNp:P:sSq")) != -1) {
		switch(c) {
			case 'f':
				input = fopen(optarg, "r");
				if (!input) {
					perror("uci");
					return 1;
				}
				break;
			case 'm':
				flags |= CLI_FLAG_MERGE;
				break;
			case 's':
				ctx->flags |= UCI_FLAG_STRICT;
				break;
			case 'S':
				ctx->flags &= ~UCI_FLAG_STRICT;
				ctx->flags |= UCI_FLAG_PERROR;
				break;
			case 'n':
				ctx->flags |= UCI_FLAG_EXPORT_NAME;
				break;
			case 'N':
				ctx->flags &= ~UCI_FLAG_EXPORT_NAME;
				break;
			case 'p':
				uci_add_history_path(ctx, optarg);
				break;
			case 'P':
				uci_add_history_path(ctx, ctx->savedir);
				uci_set_savedir(ctx, optarg);
				flags |= CLI_FLAG_NOCOMMIT;
				break;
			case 'q':
				flags |= CLI_FLAG_QUIET;
				break;
			default:
				uci_usage();
				return 0;
		}
	}
	if (optind > 1)
		argv[optind - 1] = argv[0];
	argv += optind - 1;
	argc -= optind - 1;

	if (argc < 2) {
		uci_usage();
		return 0;
	}
	ret = uci_cmd(argc - 1, argv + 1);
	if (input != stdin)
		fclose(input);
	if (ret == 255) {
		uci_usage();
		return 0;
	}

	uci_free_context(ctx);

	return ret;
}
