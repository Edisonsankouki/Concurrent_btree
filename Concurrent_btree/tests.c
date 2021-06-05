#include "btreestore.h"

int main() {
    // Your own testing code here
    void * helper = init_store(4, 4);

    close_store(helper);

    return 0;
}
