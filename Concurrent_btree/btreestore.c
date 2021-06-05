#include "btreestore.h"

int attach_node( Bnode *target_node,struct node **list, uint16_t *order)
{

   
    (*list)[(*order)].num_keys = target_node->key_num;
  
    (*list)[(*order)].keys = malloc(sizeof(uint32_t) * target_node->key_num);
    
    for (uint16_t index = 0; index < target_node->key_num; index++)
    {
        (*list)[(*order)].keys[index] = target_node->keys[index].key;
    }
    (*order)++;
    if (target_node->isleaf == False)
    {
        for (uint16_t index = 0; index < target_node->key_num; ++index)
        {
            attach_node(target_node->child_list[index], list, order);
        }
        attach_node(target_node->child_list[target_node->key_num], list, order);
    }
};

void *init_store(uint16_t branching, uint8_t n_processors)
{
    manager *helper = (manager *)malloc(sizeof(manager));
    helper->mytree = (Root *)malloc(sizeof(Root));
    helper->mytree->branch_factor = branching;
    helper->mytree->node_num = 0;
    helper->mytree->root_node = NULL;
    pthread_cond_init(&helper->con, NULL);
    helper->processor_num = n_processors;
    pthread_rwlock_init(&(helper->lock), NULL);
    pthread_mutex_init(&(helper->mutex), NULL);
    helper->current_working_num = 0;
    return (void *)helper;
}

void close_store(void *helper)
{
    manager *manager = (struct manager *)helper;
    clean_tree(manager->mytree->root_node);
    pthread_rwlock_destroy(&(manager->lock));
    pthread_cond_destroy(&(manager->con));
    pthread_mutex_destroy(&(manager->mutex));
    free(manager->mytree);
    free(manager);
}

int btree_insert(uint32_t key, void *plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void *helper)
{
    
   
    manager *manager = (struct manager *)helper;
    pthread_mutex_lock(&manager->mutex);

    while (manager->current_working_num >= manager->processor_num)
    {
        pthread_cond_wait(&(manager->con), &(manager->mutex));
    }
    manager->current_working_num++;
    pthread_mutex_unlock(&(manager->mutex));
    uint8_t last_content[8];
    int num_64 = count / 8;
    int last_bytes = count - (num_64 * 8);
    int index_count = 0;
    for (int i = 0; i < last_bytes; i++)
    {
        last_content[i] = *((uint8_t *)plaintext + (count - last_bytes + i));
        index_count += 1;
    }
    for (int i = index_count; i < 8; i++)
    {
        last_content[i] = 0;
    }

    uint64_t *the_text;
    if (index_count != 0)
    {
        the_text = malloc((sizeof(uint64_t) * (num_64 + 1)));
    }
    else
    {
        the_text = malloc((sizeof(uint64_t) * (num_64)));
    }

    uint64_t *original_text = (uint64_t *)plaintext;

    for (int i = 0; i < num_64; i++)
    {
        the_text[i] = original_text[i];
    }
    uint64_t lastone = *((uint64_t *)last_content);
    if (index_count != 0)
    {
        the_text[num_64] = lastone;
    }
    uint64_t *cipher_text;
    int blocks_num;

    if (index_count != 0)
    {
        cipher_text = malloc((sizeof(uint64_t) * (num_64 + 1)));
        blocks_num = num_64 + 1;
    }
    else
    {
        cipher_text = malloc((sizeof(uint64_t) * (num_64)));
        blocks_num = num_64;
    }

    encrypt_tea_ctr(the_text, encryption_key, nonce, cipher_text, blocks_num);
    free(the_text);

    key_obj key_to_insert;

    struct info *info_in_node = malloc(sizeof(struct info));

    info_in_node->data = cipher_text;

    info_in_node->size = count;
    info_in_node->nonce = nonce;

    for (int i = 0; i < 4; i++)
    {
        info_in_node->key[i] = encryption_key[i];
    }

    key_to_insert.key = key;

    key_to_insert.content = info_in_node;

    pthread_rwlock_wrlock(&(manager->lock));

    int result = btree_insertion(manager->mytree, key_to_insert);

    pthread_rwlock_unlock(&(manager->lock));

    pthread_mutex_lock(&(manager->mutex));

    manager->current_working_num--;

    pthread_cond_signal(&(manager->con));

    pthread_mutex_unlock(&(manager->mutex));

    if (result == 0)
    {

        return 0;
    }
    else
    {
        free(info_in_node);
        free(cipher_text);
        return 1;
    }

    
}

int btree_retrieve(uint32_t key, struct info *found, void *helper)
{
    manager *manager = (struct manager *)helper;
    pthread_mutex_lock(&manager->mutex);

    while (manager->current_working_num >= manager->processor_num)
    {
        pthread_cond_wait(&(manager->con), &(manager->mutex));
    }
    manager->current_working_num++;
    pthread_mutex_unlock(&(manager->mutex));

    pthread_rwlock_rdlock(&(manager)->lock);
    key_obj the_object = {key, NULL};

    Find result = btree_search(manager->mytree, the_object);
    pthread_rwlock_unlock(&(manager->lock));

    pthread_mutex_lock(&(manager->mutex));

    manager->current_working_num--;

    pthread_cond_signal(&(manager->con));

    pthread_mutex_unlock(&(manager->mutex));

    if (result.is_found == True)
    {
        key_obj target_key;
        for (int i = 0; i < result.result->key_num; i++)
        {
            if (key == result.result->keys[i].key)
            {
                target_key = result.result->keys[i];
            }
        }
        struct info *the_info = (struct info *)target_key.content;
        found->data = the_info->data;
        found->nonce = the_info->nonce;
        found->size = the_info->size;
        for (int i = 0; i < 4; i++)
        {
            found->key[i] = the_info->key[i];
        }
        return 0;
    }
    else
    {
        return 1;
    }
}

int btree_decrypt(uint32_t key, void *output, void *helper)
{
    
    struct info *found = malloc(sizeof(struct info));
    struct manager* manager = (struct manager*)helper;
  
    int result = btree_retrieve(key, found, helper);

    if(result == 1){
        free(found);
        return 1;
    }
    int num_block;
    if(found->size%8==0){
        num_block = found->size/8;
    }else{
        num_block = found->size/8+1;
    }
    void* my_out_put = malloc(sizeof(uint64_t)*num_block);
    decrypt_tea_ctr(found->data, found->key, found->nonce, my_out_put, num_block);
    memcpy(output,my_out_put,found->size);
    free(my_out_put);
    free(found);
    return 0;
}

int btree_delete(uint32_t key, void *helper)
{
    manager *manager = (struct manager *)helper;

    pthread_mutex_lock(&manager->mutex);

    while (manager->current_working_num >= manager->processor_num)
    {
        pthread_cond_wait(&(manager->con), &(manager->mutex));
    }
    manager->current_working_num++;
    pthread_mutex_unlock(&(manager->mutex));

    key_obj the_object = {key, NULL};
    pthread_rwlock_wrlock(&(manager->lock));

    int result = btree_deletion(manager->mytree, the_object);
    pthread_rwlock_unlock(&(manager->lock));

    pthread_mutex_lock(&(manager->mutex));

    manager->current_working_num--;

    pthread_cond_signal(&(manager->con));

    pthread_mutex_unlock(&(manager->mutex));

    if (result == -1)
    {

        return 1;
    }
    else
    {

        return 0;
    }
   
}

uint64_t btree_export(void *helper, struct node **list)
{
    
    manager *manager = (struct manager *)helper;
    if (manager->mytree->node_num == 0)
    {
        return 0;
    }

    (*list) = malloc(sizeof(struct node) * manager->mytree->node_num);
    uint16_t order = 0;
    attach_node(manager->mytree->root_node,list,&order);

    return manager->mytree->node_num;
}

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4])
{
    int sum = 0;
    int delta = 0x9E3779B9;
    cipher[0] = plain[0];
    cipher[1] = plain[1];
    for (int i = 0; i < 1024; i++)
    {
        sum = (sum + delta) % mod_num;
        int tmp1 = ((cipher[1] << 4) + key[0]) % mod_num;
        int tmp2 = ((cipher[1] + sum) % mod_num);
        int tmp3 = ((cipher[1] >> 5) + key[1]) % mod_num;
        cipher[0] = (cipher[0] + (tmp1 ^ tmp2 ^ tmp3)) % mod_num;
        int tmp4 = ((cipher[0] << 4) + key[2]) % mod_num;
        int tmp5 = (cipher[0] + sum) % mod_num;
        int tmp6 = ((cipher[0] >> 5) + key[3]) % mod_num;
        cipher[1] = (cipher[1] + (tmp4 ^ tmp5 ^ tmp6)) % mod_num;
    }

    return;
}

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4])
{
    int sum = 0xDDE6E400;
    int delta = 0x9E3779B9;
    for (int i = 0; i < 1024; i++)
    {
        int tmp4 = ((cipher[0] << 4) + key[2]) % mod_num;
        int tmp5 = (cipher[0] + sum) % mod_num;
        int tmp6 = ((cipher[0] >> 5) + key[3]) % mod_num;
        cipher[1] = (cipher[1] - (tmp4 ^ tmp5 ^ tmp6)) % mod_num;
        int tmp1 = ((cipher[1] << 4) + key[0]) % mod_num;
        int tmp2 = (cipher[1] + sum) % mod_num;
        int tmp3 = ((cipher[1] >> 5) + key[1]) % mod_num;
        cipher[0] = (cipher[0] - (tmp1 ^ tmp2 ^ tmp3)) % mod_num;
        sum = (sum - delta) % mod_num;
    }
    plain[0] = cipher[0];
    plain[1] = cipher[1];
    return;
}

void encrypt_tea_ctr(uint64_t *plain, uint32_t key[4], uint64_t nonce, uint64_t *cipher, uint32_t num_blocks)
{
     
    for (int i = 0; i < num_blocks; i++)
    {
        uint64_t tmp1 = i ^ nonce;
        uint64_t tmp2;
        encrypt_tea((uint32_t *)&tmp1, (uint32_t *)&tmp2, key);
        cipher[i] = plain[i] ^ tmp2;
    }
    return;
}

void decrypt_tea_ctr(uint64_t *cipher, uint32_t key[4], uint64_t nonce, uint64_t *plain, uint32_t num_blocks)
{
    
    encrypt_tea_ctr(cipher, key, nonce, plain, num_blocks);
    return;
}

/*btree interface*/
int btree_insertion(Root *the_tree, key_obj key)
{
    /*root may not have a root node but must be with a branch*/
    int branch_num = the_tree->branch_factor;
    /*init a root node*/

    if (the_tree->root_node == NULL)
    {

        the_tree->root_node = init_node(branch_num, key);
        the_tree->node_num += 1;

        return 0;
    }
    else
    {

        Find find_result = btree_search(the_tree, key);

        if (find_result.is_found == True)
        {
            return -1;
        }
        else
        {

            Bnode *insert_postion = find_result.result;
            /*now we need to insert in this postion*/

            
            
            if (insert_postion->key_num < branch_num - 1)
            {
                

                /*if we have space for the new key*/
                insert_postion->keys[insert_postion->key_num] = key;
                insert_postion->key_num += 1;
                sort(insert_postion->keys, insert_postion->key_num - 1);

                return 0;
            }
            else
            {
                
                /*overflow handling,splitting tree iteratively*/
                split(insert_postion, branch_num, key, the_tree);
                return 0;
            }
        }
    }
}

Find btree_search(Root *the_tree, key_obj key)
{

    Bnode *start_node = the_tree->root_node;
    /*searching internal nodes*/
    while (start_node->isleaf == False)
    {
        /*first find it in the cursor*/

        for (int i = 0; i < start_node->key_num; i++)
        {

            if (start_node->keys[i].key == key.key)
            {

                Find result_0;
                result_0.is_found = True;
                result_0.result = start_node;
                return result_0;
            }
        }
        /*if not found, go deeper*/

        for (int i = 0; i < start_node->key_num; i++)
        {
            if (start_node->keys[i].key > key.key)
            {
                start_node = start_node->child_list[i];
                break;
            }
            else
            {
                if (i == start_node->key_num - 1)
                {

                    start_node = start_node->child_list[i + 1];
                    break;
                }
            }
        }
    }

    Find result_1;
    for (int i = 0; i < start_node->key_num; i++)
    {
        if (start_node->keys[i].key == key.key)
        {
            result_1.is_found = True;
            result_1.result = start_node;
            return result_1;
        }
    }

    result_1.result = start_node;
    result_1.is_found = False;

    return result_1;
}

int btree_deletion(Root *the_tree, key_obj key)
{

    Find the_result = btree_search(the_tree, key);
    int branch_num = the_tree->branch_factor;

    if (the_result.is_found == False)
    {
        return -1;
    }
    else
    {
        Bnode *target_node = the_result.result;

        /*find the leaf node to delete with and keep swap, we always delete from a leaf node*/

        if (target_node->isleaf == True)
        {
            int key_index;

            for (int i = 0; i < target_node->key_num; i++)
            {
                if (target_node->keys[i].key == key.key)
                {
                    key_index = i;
                }
            }
            

            key_obj value = target_node->keys[key_index];
     
            target_node->keys[key_index] = target_node->keys[target_node->key_num - 1];
            target_node->keys[target_node->key_num - 1] = value;

            sort(target_node->keys,target_node->key_num-2);

    

            
        }

        if (target_node->isleaf == False)
        {
            int key_index;

            for (int i = 0; i < target_node->key_num; i++)
            {
                if (target_node->keys[i].key == key.key)
                {
                    key_index = i;
                }
            }

            Bnode *cursor = target_node->child_list[0];

            while (cursor->isleaf == False)
            {
                cursor = cursor->child_list[cursor->key_num];
            }

            key_obj value = target_node->keys[key_index];

            key_obj value1 = cursor->keys[cursor->key_num - 1];

            target_node->keys[key_index] = value1;

            cursor->keys[cursor->key_num - 1] = value;

            

            target_node = cursor;
        }

        /*now the key is in the right most of a leaf node*/
        struct info *info_ptr;
        

        if (target_node->key_num - 1 >= (branch_num - 1) / 2 || target_node->parent_node == NULL)
        {
            /*just delete*/
            int key_index;
            for (int i = 0; i < target_node->key_num; i++)
            {
                if (target_node->keys[i].key == key.key)
                {
                    key_index = i;
                }
            }
            info_ptr = target_node->keys[key_index].content;
            free(info_ptr->data);
            free(info_ptr);
            if (key_index != target_node->key_num - 1)
            {
                for (int i = key_index; i < target_node->key_num - 1; i++)
                {
                    target_node->keys[i] = target_node->keys[i + 1];
                }
            }
            target_node->key_num -= 1;
            sort(target_node->keys, target_node->key_num - 1);
        }
        else
        {

            int key_index;
            for (int i = 0; i < target_node->key_num; i++)
            {
                if (target_node->keys[i].key == key.key)
                {
                    key_index = i;
                }
            }

            info_ptr = (struct info *)target_node->keys[key_index].content;
            free(info_ptr->data);
            free(info_ptr);
            
            borrow_key(target_node, branch_num, key, the_tree);
        }
    }
    return 0;
}

Bnode *init_node(int branch_num, key_obj key)
{
    Bnode *new_node = malloc(sizeof(Bnode));
    Bnode **childlist = (Bnode **)malloc(sizeof(Bnode *) * (branch_num + 1));
    new_node->child_list = childlist;
    new_node->key_num = 1;
    key_obj *the_key_list = (key_obj *)malloc(sizeof(key_obj) * (branch_num));
    the_key_list[0] = key;
    new_node->keys = the_key_list;
    new_node->parent_node = NULL;
    new_node->isleaf = True;

    return new_node;
}

void sort(key_obj a[], int n)
{
    n++;
    for (int i = 0; i < n - 1; i++)
    {
        int isSorted = 1;

        for (int j = 0; j < n - 1 - i; j++)
        {
            if (a[j].key > a[j + 1].key)
            {
                isSorted = 0;
                key_obj temp = a[j];
                a[j] = a[j + 1];
                a[j + 1] = temp;
            }
        }
        if (isSorted)
            break;
    }
}

void split(Bnode *target_node, int branch_num, key_obj key, Root *tree)
{     
    key_obj key_to_insert = key;
    
    if (target_node->parent_node == NULL)
    {
        tree->node_num += 2;
        Bnode *left_hand = target_node;
        key_obj new_keyobj;
        new_keyobj.key = 0;
        Bnode *right_hand = init_node(branch_num, new_keyobj);
        Bnode *new_root;
        target_node->keys[target_node->key_num] = key_to_insert;
        sort(target_node->keys, target_node->key_num);
        target_node->key_num += 1;
        int key_num = target_node->key_num;
        int the_middle;
        if (key_num % 2 == 0)
        {
            the_middle = key_num / 2 - 1;
        }
        else
        {
            the_middle = key_num / 2;
        }
        key_obj middle_key = target_node->keys[the_middle];
        new_root = init_node(branch_num, middle_key);
        right_hand->key_num = key_num - 1 - the_middle;
        left_hand->key_num = the_middle;
        for (int i = 0; i < right_hand->key_num; i++)
        {
            right_hand->keys[i] = left_hand->keys[i + the_middle + 1];
        }
        new_root->child_list[0] = left_hand;
        new_root->child_list[1] = right_hand;
        left_hand->parent_node = new_root;
        right_hand->parent_node = new_root;
        new_root->isleaf = False;
        tree->root_node = new_root;
        return;
    }

    while (target_node->parent_node != NULL)
    {   
        Bnode *new_parent;
        Bnode *left_hand = target_node;
        key_obj new_keyobj;
        new_keyobj.key = 0;
        Bnode *right_hand = init_node(branch_num, new_keyobj);
        
        /*first because in a loop the target node will always change, we need to find if it is already suitable to sit a key*/
        target_node->keys[target_node->key_num] = key_to_insert;
        sort(target_node->keys, target_node->key_num);
        target_node->key_num += 1;
        
        if (target_node->key_num < branch_num)
        {
            free(right_hand->child_list);
            free(right_hand->keys);
            free(right_hand);
            return; /*if during the loop we find a suitable place to set the extra key then everything is done*/
        }
        
        int key_num = branch_num;
        int the_middle;
        if (key_num % 2 == 0)
        {
            the_middle = key_num / 2 - 1;
        }
        else
        {
            the_middle = key_num / 2;
        }
        key_obj middle_key = target_node->keys[the_middle];

        new_parent = target_node->parent_node;
        right_hand->key_num = key_num - 1 - the_middle;
        left_hand->key_num = the_middle;

      

        

        int left_hand_index;
        for(int i = 0; i <= new_parent->key_num;i++){
            if(new_parent->child_list[i]==left_hand){
                left_hand_index = i;
            }
        }

        for (int i = 0; i < right_hand->key_num; i++)
        {   
            
            right_hand->keys[i] = left_hand->keys[i + the_middle + 1];
        }

        if (target_node->isleaf == False)
        {
            
            for (int i = 0; i <= the_middle; i++)
                left_hand->child_list[i] = target_node->child_list[i];

            for (int i = 0; i < branch_num - the_middle; i++){
                
                right_hand->child_list[i] = target_node->child_list[i + 1 + the_middle];
            }

            for (int i = 0; i <= right_hand->key_num; i++)
                right_hand->child_list[i]->parent_node = right_hand;

            left_hand->isleaf = False;
            right_hand->isleaf = False;
        }
        
        
        new_parent->child_list[left_hand_index] = left_hand;
        left_hand->parent_node = new_parent;
        for(int i = new_parent->key_num+1; i>left_hand_index+1;i--){
            
            new_parent->child_list[i] = new_parent->child_list[i-1];
        }
        new_parent->child_list[left_hand_index + 1] = right_hand;
        
      
        right_hand->parent_node = new_parent;


        target_node = new_parent;
        target_node->isleaf = False;
        key_to_insert = middle_key;
        tree->node_num += 1;

        continue;
    }
    if (target_node->parent_node == NULL)
    {
        //if the loop ends and we need to insert the last to root, perform the last.
        
        Bnode *new_root;
        Bnode *left_hand = target_node;
        key_obj new_keyobj;
        new_keyobj.key = 0;
        Bnode *right_hand = init_node(branch_num, new_keyobj);

        target_node->keys[target_node->key_num] = key_to_insert;

        sort(target_node->keys, target_node->key_num);

        target_node->key_num += 1;

        if (target_node->key_num < branch_num)
        {
            free(right_hand->child_list);
            free(right_hand->keys);
            free(right_hand);
            tree->root_node = target_node;
            return;
        }

       
        int key_num = branch_num;
        int the_middle;
        if (key_num % 2 == 0)
        {
            the_middle = key_num / 2 - 1;
        }
        else
        {
            the_middle = key_num / 2;
        }
        key_obj middle_key = target_node->keys[the_middle];
        new_root = init_node(branch_num, middle_key);

        right_hand->key_num = key_num - 1 - the_middle;

        left_hand->key_num = the_middle;

        for (int i = 0; i < right_hand->key_num; i++)
            right_hand->keys[i] = left_hand->keys[i + the_middle + 1];
        for (int i = 0; i <= the_middle; i++)
            left_hand->child_list[i] = target_node->child_list[i];
        for (int i = 0; i < branch_num - the_middle; i++)
        { 
            right_hand->child_list[i] = target_node->child_list[i + 1 + the_middle];
        }
        for (int i = 0; i <= right_hand->key_num; i++)
            right_hand->child_list[i]->parent_node = right_hand;

        left_hand->isleaf = False;
        right_hand->isleaf = False;
        new_root->child_list[0] = left_hand;
        new_root->child_list[1] = right_hand;
        target_node = new_root;
        tree->root_node = target_node;
        tree->root_node->isleaf = False;
        left_hand->parent_node = target_node;
        right_hand->parent_node = target_node;
        tree->node_num += 2;
    }
}

void borrow_key(Bnode *target_node, int branch_num, key_obj key, Root *tree)
{
    target_node->key_num -= 1;


    while (target_node->parent_node != NULL)
    {
        
        
        Bnode *left_sib;
        Bnode *right_sib;
        Bnode *parent;
        parent = target_node->parent_node;
        int target_index;
        
        
        for (int i = 0; i < parent->key_num + 1; i++)
        {
            
            if (target_node->parent_node->child_list[i] == target_node)
            {
                target_index = i;
            }
        }

        if (target_index == 0)
        {
           
            right_sib = target_node->parent_node->child_list[target_index + 1];
            left_sib = NULL;
        }
        else if (target_index == parent->key_num)
        {

            left_sib = target_node->parent_node->child_list[target_index - 1];

            right_sib = NULL;
        }
        else
        {
            right_sib = target_node->parent_node->child_list[target_index + 1];
            left_sib = target_node->parent_node->child_list[target_index - 1];
        }
        if (left_sib != NULL && right_sib != NULL)
        {

            if (left_sib->key_num - 1 >= (branch_num - 1) / 2)
            { /*if left sib has enough key*/
                target_node->key_num += 1;
                for (int i = 1; i < target_node->key_num; i++)
                {
                    target_node->keys[i] = target_node->keys[i - 1];
                }
                target_node->keys[0] = parent->keys[target_index - 1];
                parent->keys[target_index - 1] = left_sib->keys[left_sib->key_num - 1];
                if (left_sib->isleaf == False)
                {
                    Bnode *C_child = left_sib->child_list[left_sib->key_num];
                    for (int i = 1; i < target_node->key_num + 1; i++)
                    {
                        target_node->child_list[i] = target_node->child_list[i - 1];
                    }
                    target_node->child_list[0] = C_child;
                    C_child->parent_node = target_node;
                }
                left_sib->key_num -= 1;

                return;
            }
            else if (right_sib->key_num - 1 >= (branch_num - 1) / 2)
            {
                target_node->key_num += 1;
                /*if right sib has enough key*/
                target_node->keys[target_node->key_num - 1] = parent->keys[target_index];

                parent->keys[target_index] = right_sib->keys[0];
                for (int i = 0; i < right_sib->key_num - 1; i++)
                {
                    right_sib->keys[i] = right_sib->keys[i + 1];
                }

                if (right_sib->isleaf == False)
                {

                    Bnode *C_child = right_sib->child_list[0];
                    for (int i = 0; i < right_sib->key_num; i++)
                    {
                        right_sib->child_list[i] = right_sib->child_list[i + 1];
                    }
                    if (target_node->key_num - 1 != 0)
                    {
                        target_node->child_list[target_node->key_num - 1] = C_child;
                    }
                    else
                    {
                        target_node->child_list[target_node->key_num] = C_child;
                    }
                    C_child->parent_node = target_node;
                }
                right_sib->key_num -= 1;

                return;
            }
            else
            {
                tree->node_num-=1;
                key_obj *key_array = malloc(sizeof(key_obj) * (left_sib->key_num + 1 + target_node->key_num));
                for (int i = 0; i < left_sib->key_num; i++)
                {
                    key_array[i] = left_sib->keys[i];
                }
                key_array[left_sib->key_num] = parent->keys[target_index - 1];
                for (int i = left_sib->key_num + 1; i < left_sib->key_num + target_node->key_num + 1; i++)
                {
                    key_array[i] = target_node->keys[i - left_sib->key_num - 1];
                }

                
                if (target_node->isleaf == False)
                {

                    Bnode **new_child_list = malloc(sizeof(Bnode *) * (target_node->key_num + 2 + left_sib->key_num));
                    for (int i = 0; i < left_sib->key_num + 1; i++)
                    {
                        new_child_list[i] = left_sib->child_list[i];
                    }

                    for (int i = left_sib->key_num + 1; i < target_node->key_num + 2 + left_sib->key_num; i++)
                    {
                        new_child_list[i] = target_node->child_list[i - left_sib->key_num - 1];
                    }
                    for (int i = 0; i < target_node->key_num + 2 + left_sib->key_num; i++)
                    {
                        new_child_list[i]->parent_node = target_node;
                    }
                    free(target_node->child_list);
                    target_node->child_list = NULL;
                    target_node->child_list = new_child_list;
                }
                for (int i = target_index - 1; i < parent->key_num - 1; i++)
                {
                    parent->keys[i] = parent->keys[i + 1];
                }
                for (int i = target_index - 1; i < parent->key_num; i++)
                {
                    parent->child_list[i] = parent->child_list[i + 1];
                }

                free(target_node->keys);
                target_node->keys = NULL;
                target_node->keys = key_array;
                target_node->key_num = left_sib->key_num + 1 + target_node->key_num;
                free(left_sib->keys);
                left_sib->keys = NULL;
                free(left_sib->child_list);
                left_sib->child_list = NULL;
                free(left_sib);
                left_sib = NULL;
                parent->key_num -= 1;
                if (parent->key_num < (branch_num - 1 / 2))
                {
                    target_node = parent;
                    continue;
                }
                else
                {
                    return;
                }
            }
        }
        if (right_sib == NULL)
        {

            if (left_sib->key_num - 1 >= (branch_num - 1) / 2)
            {

                target_node->key_num += 1;
                for (int i = 1; i < target_node->key_num; i++)
                {
                    target_node->keys[i] = target_node->keys[i - 1];
                }
                target_node->keys[0] = parent->keys[target_index - 1];
                parent->keys[target_index - 1] = left_sib->keys[left_sib->key_num - 1];
                if (left_sib->isleaf == False)
                {
                    Bnode *C_child = left_sib->child_list[left_sib->key_num];
                    for (int i = 1; i < target_node->key_num + 1; i++)
                    {
                        target_node->child_list[i] = target_node->child_list[i - 1];
                    }
                    target_node->child_list[0] = C_child;
                    C_child->parent_node = target_node;
                }
                left_sib->key_num -= 1;

                return;
            }
            else
            {
                tree->node_num -= 1;
                key_obj *key_array = malloc(sizeof(key_obj) * (left_sib->key_num + 1 + target_node->key_num));
                for (int i = 0; i < left_sib->key_num; i++)
                {
                    key_array[i] = left_sib->keys[i];
                }
                key_array[left_sib->key_num] = parent->keys[target_index - 1];
                for (int i = left_sib->key_num + 1; i < left_sib->key_num + target_node->key_num + 1; i++)
                {
                    key_array[i] = target_node->keys[i - left_sib->key_num - 1];
                }
               

                if (target_node->isleaf == False)
                {
                    Bnode **new_child_list = malloc(sizeof(Bnode *) * (target_node->key_num + 2 + left_sib->key_num));
                    for (int i = 0; i < left_sib->key_num + 1; i++)
                    {
                        new_child_list[i] = left_sib->child_list[i];
                    }
                    for (int i = left_sib->key_num + 1; i < target_node->key_num + 2 + left_sib->key_num; i++)
                    {
                        new_child_list[i] = target_node->child_list[i - left_sib->key_num - 1];
                    }
                    for (int i = 0; i < target_node->key_num + 2 + left_sib->key_num; i++)
                    {
                        new_child_list[i]->parent_node = target_node;
                    }
                    free(target_node->child_list);
                    target_node->child_list = NULL;
                    target_node->child_list = new_child_list;
                }

                for (int i = target_index - 1; i < parent->key_num - 1; i++)
                {
                    parent->keys[i] = parent->keys[i + 1];
                }
                for (int i = target_index - 1; i < parent->key_num; i++)
                {
                    parent->child_list[i] = parent->child_list[i + 1];
                }

                free(target_node->keys);
                target_node->keys = NULL;
                target_node->keys = key_array;
                target_node->key_num = left_sib->key_num + 1 + target_node->key_num;
                parent->key_num -= 1;

                free(left_sib->keys);
                left_sib->keys = NULL;
                free(left_sib->child_list);
                left_sib->child_list = NULL;
                free(left_sib);
                left_sib = NULL;

                if (parent->key_num < (branch_num - 1 / 2))
                {
                    target_node = parent;
                    continue;
                }
                else
                {

                    return;
                }
            }
        }

        if (left_sib == NULL)
        {   
           
            //chercked
            if (right_sib->key_num - 1 >= (branch_num - 1) / 2)
            {

               
                target_node->key_num += 1;
                 
                target_node->keys[target_node->key_num - 1] = parent->keys[target_index];
                parent->keys[target_index] = right_sib->keys[0];
                for (int i = 0; i < right_sib->key_num - 1; i++)
                {
                    right_sib->keys[i] = right_sib->keys[i + 1];
                }
                if (right_sib->isleaf == False)
                {
                    Bnode *C_child = right_sib->child_list[0];
                    for (int i = 0; i < right_sib->key_num; i++)
                    {
                        right_sib->child_list[i] = right_sib->child_list[i + 1];
                    }
                    if (target_node->key_num - 1 != 0)
                    {
                        
                        target_node->child_list[target_node->key_num] = C_child;
                    }
                    else
                    {
                        target_node->child_list[target_node->key_num] = C_child;
                    }
                    C_child->parent_node = target_node;
                }
                right_sib->key_num -= 1;

                return;
            }
            //checked
            else
            {
              
                tree->node_num -= 1;
               
                key_obj *key_array = malloc(sizeof(key_obj) * (right_sib->key_num + 1 + target_node->key_num));
                for (int i = 0; i < target_node->key_num; i++)
                {
                  
                    key_array[i] = target_node->keys[i];
                }
                key_array[target_node->key_num] = parent->keys[0];
                for (int i = target_node->key_num + 1; i < right_sib->key_num + target_node->key_num + 1; i++)
                {
                    key_array[i] = right_sib->keys[i - target_node->key_num - 1];
                }
                for(int i = 0; i <right_sib->key_num + 1 + target_node->key_num;i++){
                  
                }

                if (target_node->isleaf == False)
                {
                    Bnode **new_child_list = malloc(sizeof(Bnode *) * (right_sib->key_num + 2 + target_node->key_num));
                    int count = 0;
                    for (int i = 0; i < target_node->key_num + 1; i++)
                    {
                        new_child_list[i] = target_node->child_list[i];
                        count += 1;
                    }
                    for (int i = count; i < right_sib->key_num + 2 + target_node->key_num; i++)
                    {
                        new_child_list[i] = right_sib->child_list[i - right_sib->key_num];
                    }

                    for (int i = 0; i < right_sib->key_num + 2 + target_node->key_num; i++)
                    {
                        new_child_list[i]->parent_node = target_node;
                    }

                    free(target_node->child_list);
                    target_node->child_list = NULL;
                    target_node->child_list = new_child_list;
                }
                if (target_index != 0)
                {
                    for (int i = target_index - 1; i < parent->key_num - 1; i++)
                    {

                        parent->keys[i] = parent->keys[i + 1];
                    }
                    for (int i = target_index + 1; i < parent->key_num; i++)
                    {
                        parent->child_list[i] = parent->child_list[i + 1];
                    }
                }
                else
                {
                    for (int i = 0; i < parent->key_num - 1; i++)
                    {
                        parent->keys[i] = parent->keys[i + 1];
                    }
                    for (int i = target_index + 1; i < parent->key_num; i++)
                    {
                        parent->child_list[i] = parent->child_list[i + 1];
                    }
                }

                free(target_node->keys);

                target_node->keys = NULL;

                target_node->keys = key_array;

                target_node->key_num = right_sib->key_num + 1 + target_node->key_num;

                free(right_sib->keys);
                right_sib->keys = NULL;

                free(right_sib->child_list);
                right_sib->child_list = NULL;

                free(right_sib);
                right_sib = NULL;

                parent->key_num -= 1;

                

               

                if (parent->key_num < (branch_num - 1) / 2)
                {

                    target_node = parent;

                    continue;
                }
                else
                {

                    return;
                }
            }
        }
    }
    if (target_node->parent_node == NULL)
    {
        
        
        tree->node_num -= 1;
        if (target_node->isleaf == True)
        {
            tree->root_node = NULL;
            free(target_node->child_list);
            target_node->child_list = NULL;
            free(target_node->keys);
            target_node->keys = NULL;
            free(target_node);
            
            
        }
        else if(target_node->key_num>=1){
            tree->node_num += 1;
            return;
        }
        else
        {
            
            Bnode *left_sib = target_node->child_list[0];
            Bnode *right_sib = target_node->child_list[1];
            int is_alone;
            if (target_node->key_num == 0)
            {
                is_alone = True;
            }
            else
            {
                is_alone = False;
            }
            if(is_alone==True){
                for(int i = 0; i < target_node->key_num+1;i++){
                    target_node->child_list[i]->parent_node = NULL;
                }
                tree->root_node = left_sib;
                free(target_node->child_list);
                target_node->child_list = NULL;
                free(target_node->keys);
                target_node->keys = NULL;
                free(target_node);
                target_node = NULL;
                return;
            }
            key_obj *key_array;
            key_array =malloc(sizeof(key_obj) * (right_sib->key_num + 1 + target_node->key_num));
            for (int i = 0; i < left_sib->key_num; i++)
            {
                key_array[i] = left_sib->keys[i];
            }

            if (is_alone == False)
            {
                for (int i = left_sib->key_num; i < left_sib->key_num + right_sib->key_num; i++)
                {

                    key_array[i] = right_sib->keys[i - left_sib->key_num];
                }
            }

            free(left_sib->keys);
            left_sib->keys = NULL;
            left_sib->keys = key_array;

            Bnode **new_child_list = malloc(sizeof(Bnode *) * (right_sib->key_num + 2 + left_sib->key_num));
            int count = 0;
            for (int i = 0; i < left_sib->key_num + 1; i++)
            {
                new_child_list[i] = left_sib->child_list[i];
                count += 1;
            }
            if (is_alone == False)
            {
                for (int i = count; i < right_sib->key_num + 2 + left_sib->key_num; i++)
                {
                    new_child_list[i] = right_sib->child_list[i - right_sib->key_num];
                }
                for (int i = 0; i < right_sib->key_num + 2 + left_sib->key_num; i++)
                {
                    new_child_list[i]->parent_node = left_sib;
                }
            }
            free(left_sib->child_list);
            left_sib->child_list = NULL;
            left_sib->child_list = new_child_list;
            if (is_alone == False)
            {
                free(right_sib->child_list);
                right_sib->child_list = NULL;
                free(right_sib->keys);
                right_sib->keys = NULL;
                free(right_sib);
                right_sib->keys = NULL;
            }

            tree->root_node = left_sib;

            free(target_node->keys);
            target_node->keys = NULL;
            free(target_node->child_list);
            target_node->child_list = NULL;
            free(target_node);
            target_node = NULL;
        }
    }
}

void clean_tree(Bnode *root)
{
    
    if (root->isleaf == False)
    {

        for (int i = 0; i < root->key_num + 1; i++)
        {

            clean_tree(root->child_list[i]);
        }
    }

    
    for (int i = 0; i < root->key_num; i++)
    {
        free(((struct info *)root->keys[i].content)->data);
        free(root->keys[i].content);
    }

    free(root->child_list);

    free(root->keys);

    free(root);
}
