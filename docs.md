
# misc notes

operations to be implemented
- insert new files/directories
- delete files/directories
- rename files/directories (change metadata)

hashing function: sha384

## directory nodes

child hashes are sorted in numerical order asc

dir_node_hash = hash(meta_hash, child_hash_1, child_hash_2, ..., child_hash_n)

## file/leaf nodes

leaf_hash = hash(meta_hash, content_hash)

# get meta
GET /node/<hash>
{
    "metadata": "semi-krypterad blob",
    "type": "file|directory",
    "data_url": "signerad url om type=file",
    "tree_context": "bla"
}


# list procedure
GET /node/<hash>/children
{
    "children": [
        {
            "hash": "sha384",
            "metadata": "semi-krypterad blob",
            "type": "file|directory",
            "data_url": "signerad url om type=file"
        }
    ]
}

# insert procedure:

POST /insert
{
    "metadata": "base64 av krypterad data",
    "type": "directory|file",
    "parent": "sha256",

    // endast om type=file
    "content_hash": "sha256 av KBLOB",
    "content_length": 5391 (bytes)
}
    {
        "upload_url": "https://spaces.digitalocean/q1fs_bucket/namespace/sha256?bytes=5391&signature=blabla",
        "old_tree_context": ...,
        "new_tree_context": ...,
        "new_top_hash": ""
    }


# delete procedure


POST /delete
{
    "hash": "sha384",

    // endast om type=file
    "content_hash": "sha256 av KBLOB",
    "content_length": 5391 (bytes)
}
{
    "upload_url": "https://spaces.digitalocean/q1fs_bucket/namespace/sha256?bytes=5391&signature=blabla",
    "old_tree_context": ...,
    "new_tree_context": ...,
    "new_top_hash": ""
}


# DB

för att göra dbn effektivare när man har flera träd bör noderna klumpas ihop på nära fysiska platser, kan göras med ööh..todo, glum tables