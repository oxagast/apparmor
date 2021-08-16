/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2013 Canonical Ltd. (All rights reserved)
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Wrapper around the dfa to convert aa rules into a dfa
 */

#include <ostream>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ext/stdio_filebuf.h>
#include <assert.h>
#include <stdlib.h>

#include "aare_rules.h"
#include "expr-tree.h"
#include "parse.h"
#include "hfa.h"
#include "chfa.h"
#include "../immunix.h"


aare_rules::~aare_rules(void)
{
	if (root)
		root->release();

	unique_perms.clear();
	expr_map.clear();
}

bool aare_rules::add_rule(const char *rule, int deny, uint32_t perms,
			  uint32_t audit, dfaflags_t flags)
{
	return add_rule_vec(deny, perms, audit, 1, &rule, flags, false);
}

void aare_rules::add_to_rules(Node *tree, Node *perms)
{
	if (reverse)
		flip_tree(tree);
	Node *base = expr_map[perms];
	if (base)
		expr_map[perms] = new AltNode(base, tree);
	else
		expr_map[perms] = tree;
}

static Node *cat_with_null_separator(Node *l, Node *r)
{
	return new CatNode(new CatNode(l, new CharNode(0)), r);
}

static Node *cat_with_oob_separator(Node *l, Node *r)
{
	return new CatNode(new CatNode(l, new CharNode(transchar(-1, true))), r);
}

bool aare_rules::add_rule_vec(int deny, uint32_t perms, uint32_t audit,
			      int count, const char **rulev, dfaflags_t flags,
			      bool oob)
{
	Node *tree = NULL, *accept;
	int exact_match;

	if (regex_parse(&tree, rulev[0]))
		return false;
	for (int i = 1; i < count; i++) {
		Node *subtree = NULL;
		if (regex_parse(&subtree, rulev[i]))
			goto err;
		if (oob)
			tree = cat_with_oob_separator(tree, subtree);
		else
			tree = cat_with_null_separator(tree, subtree);
	}

	/*
	 * Check if we have an expression with or without wildcards. This
	 * determines how exec modifiers are merged in accept_perms() based
	 * on how we split permission bitmasks here.
	 */
	exact_match = 1;
	for (depth_first_traversal i(tree); i && exact_match; i++) {
		if ((*i)->is_type(NODE_TYPE_STAR) ||
		    (*i)->is_type(NODE_TYPE_PLUS) ||
		    (*i)->is_type(NODE_TYPE_ANYCHAR) ||
		    (*i)->is_type(NODE_TYPE_CHARSET) ||
		    (*i)->is_type(NODE_TYPE_NOTCHARSET))
			exact_match = 0;
	}

	if (reverse)
		flip_tree(tree);

	accept = unique_perms.insert(deny, perms, audit, exact_match);

	if (flags & DFA_DUMP_RULE_EXPR) {
		const char *separator;
		if (oob)
			separator = "\\-x01";
		else
			separator = "\\x00";
		cerr << "rule: ";
		cerr << rulev[0];
		for (int i = 1; i < count; i++) {
			cerr << separator;
			cerr << rulev[i];
		}
		cerr << "  ->  ";
		tree->dump(cerr);
		if (deny)
			cerr << " deny";
		cerr << " (0x" << hex << perms <<"/" << audit << dec << ")";
		accept->dump(cerr);
 		cerr << "\n\n";
	}

	add_to_rules(tree, accept);

	rule_count++;

	return true;

err:
	delete tree;
	return false;
}

/*
 * append_rule is like add_rule, but appends the rule to any existing rules
 * with a separating transition. The appended rule matches with the same
 * permissions as the rule it's appended to. If there are no existing rules
 * append_rule returns true.
 *
 * This is used by xattrs matching where, after matching the path, the DFA is
 * advanced by a null character for each xattr.
 */
bool aare_rules::append_rule(const char *rule, bool oob, bool with_perm,
			     dfaflags_t flags)
{
	Node *tree = NULL;
	if (regex_parse(&tree, rule))
		return false;

	if (flags & DFA_DUMP_RULE_EXPR) {
		cerr << "rule: ";
		cerr << rule;
		cerr << "  ->  ";
		tree->dump(cerr);
		cerr << "\n\n";
	}

	/*
	 * For each matching state, we want to create an optional path
	 * separated by a separating character.
	 *
	 * When matching xattrs, the DFA must end up in an accepting state for
	 * the path, then each value of the xattrs. Using an optional node
	 * lets each rule end up in an accepting state.
	 */
	tree = new CatNode(oob ? new CharNode(transchar(-1, true)) : new CharNode(0), tree);
	if (expr_map.size() == 0) {
		// There's nothing to append to. Free the tree reference.
		delete tree;
		return true;
	}
	PermExprMap::iterator it;
	for (it = expr_map.begin(); it != expr_map.end(); it++) {
		if (with_perm)
			expr_map[it->first] = new CatNode(it->second, new AltNode(it->first, tree));
		else
			expr_map[it->first] = new CatNode(it->second, tree);
	}
	return true;
}

/* create a dfa from the ruleset
 * returns: buffer contain dfa tables, @size set to the size of the tables
 *          else NULL on failure, @min_match_len set to the shortest string
 *          that can match the dfa for determining xmatch priority.
 */
void *aare_rules::create_dfa(size_t *size, int *min_match_len, dfaflags_t flags,
			     bool filedfa)
{
	char *buffer = NULL;

	/* finish constructing the expr tree from the different permission
	 * set nodes */
	PermExprMap::iterator i = expr_map.begin();
	if (i != expr_map.end()) {
		if (flags & DFA_CONTROL_TREE_SIMPLE) {
			Node *tmp = simplify_tree(i->second, flags);
			root = new CatNode(tmp, i->first);
		} else
			root = new CatNode(i->second, i->first);
		for (i++; i != expr_map.end(); i++) {
			Node *tmp;
			if (flags & DFA_CONTROL_TREE_SIMPLE) {
				tmp = simplify_tree(i->second, flags);
			} else
				tmp = i->second;
			root = new AltNode(root, new CatNode(tmp, i->first));
		}
	}
	*min_match_len = root->min_match_len();

	/* dumping of the none simplified tree without -O no-expr-simplify
	 * is broken because we need to build the tree above first, and
	 * simplification is woven into the build. Reevaluate how to fix
	 * this debug dump.
	 */
	label_nodes(root);
	if (flags & DFA_DUMP_TREE) {
		cerr << "\nDFA: Expression Tree\n";
		root->dump(cerr);
		cerr << "\n\n";
	}

	if (flags & DFA_CONTROL_TREE_SIMPLE) {
		/* This is old total tree, simplification point
		 * For now just do simplification up front. It gets most
		 * of the benefit running on the smaller chains, and is
		 * overall faster because there are less nodes. Reevaluate
		 * once tree simplification is rewritten
		 */
		//root = simplify_tree(root, flags);

		if (flags & DFA_DUMP_SIMPLE_TREE) {
			cerr << "\nDFA: Simplified Expression Tree\n";
			root->dump(cerr);
			cerr << "\n\n";
		}
	}

	stringstream stream;
	try {
		DFA dfa(root, flags, filedfa);
		if (flags & DFA_DUMP_UNIQ_PERMS)
			dfa.dump_uniq_perms("dfa");

		if (flags & DFA_CONTROL_MINIMIZE) {
			dfa.minimize(flags);

			if (flags & DFA_DUMP_MIN_UNIQ_PERMS)
				dfa.dump_uniq_perms("minimized dfa");
		}

		if (flags & DFA_CONTROL_FILTER_DENY &&
		    flags & DFA_CONTROL_MINIMIZE &&
		    dfa.apply_and_clear_deny()) {
			/* Do a second minimization pass as removal of deny
			 * information has moved some states from accepting
			 * to none accepting partitions
			 *
			 * TODO: add this as a tail pass to minimization
			 *       so we don't need to do a full second pass
			 */
			dfa.minimize(flags);

			if (flags & DFA_DUMP_MIN_UNIQ_PERMS)
				dfa.dump_uniq_perms("minimized dfa");
		}

		if (flags & DFA_CONTROL_REMOVE_UNREACHABLE)
			dfa.remove_unreachable(flags);

		if (flags & DFA_DUMP_STATES)
			dfa.dump(cerr);

		if (flags & DFA_DUMP_GRAPH)
			dfa.dump_dot_graph(cerr);

		map<transchar, transchar> eq;
		if (flags & DFA_CONTROL_EQUIV) {
			eq = dfa.equivalence_classes(flags);
			dfa.apply_equivalence_classes(eq);

			if (flags & DFA_DUMP_EQUIV) {
				cerr << "\nDFA equivalence class\n";
				dump_equivalence_classes(cerr, eq);
			}
		} else if (flags & DFA_DUMP_EQUIV)
			cerr << "\nDFA did not generate an equivalence class\n";

		if (flags & DFA_CONTROL_DIFF_ENCODE) {
			dfa.diff_encode(flags);

			if (flags & DFA_DUMP_DIFF_ENCODE)
				dfa.dump_diff_encode(cerr);
		}

		CHFA chfa(dfa, eq, flags);
		if (flags & DFA_DUMP_TRANS_TABLE)
			chfa.dump(cerr);
		chfa.flex_table(stream, "");
	}
	catch(int error) {
		*size = 0;
		return NULL;
	}

	stringbuf *buf = stream.rdbuf();

	buf->pubseekpos(0);
	*size = buf->in_avail();

	buffer = (char *)malloc(*size);
	if (!buffer)
		return NULL;
	buf->sgetn(buffer, *size);
	return buffer;
}
