#ifndef BTREESTORE_H
#define BTREESTORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>


#define mod_num 4294967296
#define True 1
#define False 0


struct Bnode{
    uint16_t key_num;
    struct key_obj* keys;
    struct Bnode* parent_node;
    struct Bnode** child_list;
    uint8_t isleaf;
}typedef Bnode;

struct Root{
    uint16_t branch_factor;

    struct Bnode* root_node;

    uint64_t node_num;
    
}typedef Root;

struct Find_result{
    struct Bnode* result;
    uint8_t is_found;

}typedef Find;

struct key_obj{
    uint32_t key;
    void* content;
}typedef key_obj;

struct info {
    uint32_t size;
    uint32_t key[4];
    uint64_t nonce;
    void * data;
};

struct node {
    uint16_t num_keys;
    uint32_t * keys;
};

struct manager{
    Root* mytree;

    uint8_t processor_num;

    pthread_rwlock_t lock;

    pthread_cond_t con;

    pthread_mutex_t mutex;

    uint8_t current_working_num;
}typedef manager;




int btree_insertion(Root* the_tree, key_obj key);
int btree_deletion(Root* the_tree, key_obj key);
Find btree_search(Root* the_tree, key_obj key);
void clean_tree(Bnode* root_node);

void * init_store(uint16_t branching, uint8_t n_processors);

void close_store(void * helper);

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper);

int btree_retrieve(uint32_t key, struct info * found, void * helper);

int btree_decrypt(uint32_t key, void * output, void * helper);

int btree_delete(uint32_t key, void * helper);

uint64_t btree_export(void * helper, struct node ** list);

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]);

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]);

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks);

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks);

void borrow_key(Bnode *target_node, int branch_num, key_obj key, Root *tree);
void split(Bnode *target_node, int branch_num, key_obj key, Root *tree);
Bnode *init_node(int branch_num, key_obj key);
void sort(key_obj a[], int n);
void clean_tree(Bnode *root_node);



#endif