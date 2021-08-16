/*
 *   Copyright (c) 2012
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */
#ifndef __AA_PROFILE_H
#define __AA_PROFILE_H

#include <set>
#include <string>
#include <iostream>

#include "capability.h"
#include "parser.h"
#include "rule.h"
#include "libapparmor_re/aare_rules.h"
#include "network.h"

class Profile;

class block {
public:

};


struct deref_profileptr_lt {
	bool operator()(Profile * const &lhs, Profile * const &rhs) const;
};

class ProfileList {
public:
	set<Profile *, deref_profileptr_lt> list;

	typedef set<Profile *, deref_profileptr_lt>::iterator iterator;
	iterator begin() { return list.begin(); }
	iterator end() { return list.end(); }

	ProfileList() { };
	virtual ~ProfileList() { clear(); }
	virtual bool empty(void) { return list.empty(); }
	virtual pair<ProfileList::iterator,bool> insert(Profile *);
	virtual void erase(ProfileList::iterator pos);
	void clear(void);
	void dump(void);
	void dump_profile_names(bool children);
};

extern const char*profile_mode_table[];
/* use profile_mode_packed to convert to the packed representation */
enum profile_mode {
	MODE_UNSPECIFIED = 0,
	MODE_ENFORCE = 1,
	MODE_COMPLAIN = 2,
	MODE_KILL = 3,
	MODE_UNCONFINED = 4,
	MODE_CONFLICT = 5	/* greater than MODE_LAST */
};
#define MODE_LAST MODE_UNCONFINED

static inline enum profile_mode operator++(enum profile_mode &mode)
{
	mode = (enum profile_mode)((int) mode + 1);
	return mode;
}

static inline enum profile_mode merge_profile_mode(enum profile_mode l, enum profile_mode r)
{
	if (l == r || r == MODE_UNSPECIFIED)
		return l;
	else if (l == MODE_UNSPECIFIED)
		return r;
	return MODE_CONFLICT;
}

static inline uint32_t profile_mode_packed(enum profile_mode mode)
{
	/* kernel doesn't have an unspecified mode everything
	 * shifts down by 1
	 */
	if ((uint32_t) mode)
		return (uint32_t) mode - 1;
	/* unspecified defaults to same as enforce */
	return 0;
}

static inline void mode_dump(ostream &os, enum profile_mode mode)
{
	if (mode <= MODE_LAST)
		os << profile_mode_table[(int) mode];
	else
		os << "unknown";
}

static inline enum profile_mode str_to_mode(const char *str)
{
	for (enum profile_mode i = MODE_ENFORCE; i <= MODE_LAST; ++i) {
		if (strcmp(profile_mode_table[i], str) == 0)
			return i;
	}

	return MODE_UNSPECIFIED;
};

class flagvals {
public:
	int hat;
	enum profile_mode mode;
	int audit;
	int path;

	ostream &dump(ostream &os)
	{
		os << "Mode: ";
		mode_dump(os, mode);
		if (audit)
			os << ", Audit";

		if (hat)
			os << ", Hat";

		os << "\n";

		return os;
	}
	ostream &debug(ostream &os)
	{
#ifdef DEBUG
		return dump(os);
#else
		return os;
#endif
	}

};

struct capabilities {
	uint64_t allow;
	uint64_t audit;
	uint64_t deny;
	uint64_t quiet;

	capabilities(void) { allow = audit = deny = quiet = 0; }

	void dump()
		{
			if (allow != 0ull)
				__debug_capabilities(allow, "Capabilities");
			if (audit != 0ull)
				__debug_capabilities(audit, "Audit Caps");
			if (deny != 0ull)
				__debug_capabilities(deny, "Deny Caps");
			if (quiet != 0ull)
				__debug_capabilities(quiet, "Quiet Caps");
		};
};

struct dfa_stuff {
	aare_rules *rules;
	void *dfa;
	size_t size;

	dfa_stuff(void): rules(NULL), dfa(NULL), size(0) { }
};

class Profile {
public:
	char *ns;
	char *name;
	char *attachment;
	struct alt_name *altnames;
	void *xmatch;
	size_t xmatch_size;
	int xmatch_len;

	struct cond_entry_list xattrs;

	/* char *sub_name; */			/* subdomain name or NULL */
	/* int default_deny; */			/* TRUE or FALSE */
	int local;
	int local_mode;				/* true if local, not hat */
	int local_audit;

	Profile *parent;

	flagvals flags;
	struct capabilities caps;
	struct network net;

	struct aa_rlimits rlimits;

	char *exec_table[AA_EXEC_COUNT];
	struct cod_entry *entries;
	RuleList rule_ents;

	ProfileList hat_table;

	struct dfa_stuff dfa;
	struct dfa_stuff policy;

	Profile(void)
	{
		ns = name = attachment = NULL;
		altnames = NULL;
		xmatch = NULL;
		xmatch_size = 0;
		xmatch_len = 0;

		xattrs.list = NULL;
		xattrs.name = NULL;

		local = local_mode = local_audit = 0;

		parent = NULL;

		flags = { 0, MODE_UNSPECIFIED, 0, 0 };
		rlimits = {0, {}};

		std::fill(exec_table, exec_table + AA_EXEC_COUNT, (char *)NULL);

		entries = NULL;
	};

	virtual ~Profile();

	bool operator<(Profile const &rhs)const
	{
		if (ns) {
			if (rhs.ns) {
				int res = strcmp(ns, rhs.ns);
				if (res != 0)
					return res < 0;
			} else
				return false;
		} else if (rhs.ns)
			return true;
		return strcmp(name, rhs.name) < 0;
	}

	void dump(void)
	{
		if (ns)
			printf("Ns:\t\t%s\n", ns);

		if (name)
			printf("Name:\t\t%s\n", name);
		else
			printf("Name:\t\t<NULL>\n");

		if (local) {
			if (parent)
				printf("Local To:\t%s\n", parent->name);
			else
				printf("Local To:\t<NULL>\n");
		}

		flags.dump(cerr);
		caps.dump();
		net.dump();

		if (entries)
			debug_cod_entries(entries);

		for (RuleList::iterator i = rule_ents.begin(); i != rule_ents.end(); i++) {
			(*i)->dump(cout);
		}

		printf("\n");
		hat_table.dump();
	}

	bool alloc_net_table();

	std::string hname(void)
	{
		if (!parent)
			return name;

		return parent->hname() + "//" + name;
	}

	/* assumes ns is set as part of profile creation */
	std::string fqname(void)
	{
		if (parent)
			return parent->fqname() + "//" + name;
		else if (!ns)
			return hname();
		return ":" + std::string(ns) + "://" + hname();
	}

	std::string get_name(bool fqp)
	{
		if (fqp)
			return fqname();
		return hname();
	}

	void dump_name(bool fqp)
	{
		cout << get_name(fqp);;
	}
};


#endif /* __AA_PROFILE_H */
