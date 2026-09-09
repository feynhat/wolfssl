typedef struct {
    byte *data;
    size_t length;
} Entry;

typedef struct TreeNode {
    byte data[SHA256_DIGEST_SIZE];
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;

size_t merkle_split(size_t);
void build_mt(TreeNode *, const Entry [], size_t);
void build_mt_subtree(TreeNode *, const Entry [], size_t, size_t);
void build_mt_str(TreeNode *, const char *[], size_t);
size_t subtree_inclusion_proof(byte **, const Entry[], size_t, size_t, size_t);
size_t subtree_inclusion_proof_allocated(byte **, const Entry[], size_t, size_t, size_t);
size_t subtree_inclusion_proof_size(size_t, size_t, size_t);
size_t subtree_proof(byte **, const Entry[], size_t, size_t, size_t);
size_t subtree_subproof(byte **, const Entry[], size_t, size_t, size_t, size_t, unsigned);

void mt_hash(byte [], const Entry [], size_t, size_t);

int is_valid_subtree(word64, word64);

void free_subtree(TreeNode *);
void free_tree_children(TreeNode *);

void hash_leaf(byte [SHA256_DIGEST_SIZE], const Entry *);
void hash_internal(byte [], const byte [], const byte []);

int evaluate_inclusion_proof(word64, word64, word64, byte [], const byte *, size_t);

size_t read_inclusion_proof(byte **);
void read_hash(byte []);
int hex_digit(char c);

void hash_to_str(char *, const byte[]);
void print_full_hash(const byte [SHA256_DIGEST_SIZE]);
void print_tree(const TreeNode *);
void print_tree_recursive(const TreeNode *, const char *, int, const char *);
