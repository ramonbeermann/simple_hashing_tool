#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>

#define HASH_SIZE 65
#define MAX_THREADS 4  // Anzahl paralleler Hash-Scans
#define VIRUS_DB "virus_hashes.txt"

typedef struct {
    char filepath[1024];
} ScanTask;

void compute_hashes(const char *filename, char *md5_hash, char *sha1_hash, char *sha256_hash) {
    unsigned char data[1024];
    unsigned char md5_result[MD5_DIGEST_LENGTH], sha1_result[SHA_DIGEST_LENGTH], sha256_result[SHA256_DIGEST_LENGTH];
    MD5_CTX md5_ctx;
    SHA_CTX sha1_ctx;
    SHA256_CTX sha256_ctx;
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Fehler beim Öffnen der Datei");
        return;
    }

    MD5_Init(&md5_ctx);
    SHA1_Init(&sha1_ctx);
    SHA256_Init(&sha256_ctx);

    size_t bytes;
    while ((bytes = fread(data, 1, sizeof(data), file)) != 0) {
        MD5_Update(&md5_ctx, data, bytes);
        SHA1_Update(&sha1_ctx, data, bytes);
        SHA256_Update(&sha256_ctx, data, bytes);
    }

    MD5_Final(md5_result, &md5_ctx);
    SHA1_Final(sha1_result, &sha1_ctx);
    SHA256_Final(sha256_result, &sha256_ctx);
    fclose(file);

    // Ergebnisse als hexadezimale Strings speichern
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) sprintf(&md5_hash[i * 2], "%02x", md5_result[i]);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) sprintf(&sha1_hash[i * 2], "%02x", sha1_result[i]);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(&sha256_hash[i * 2], "%02x", sha256_result[i]);
}

int is_virus(const char *hash) {
    FILE *file = fopen(VIRUS_DB, "r");
    if (!file) return 0;
    
    char line[HASH_SIZE];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(hash, line, strlen(hash)) == 0) {
            fclose(file);
            return 1;
        }
    }
    
    fclose(file);
    return 0;
}

void* scan_file(void *arg) {
    ScanTask *task = (ScanTask*)arg;
    char md5_hash[HASH_SIZE] = {0}, sha1_hash[HASH_SIZE] = {0}, sha256_hash[HASH_SIZE] = {0};

    compute_hashes(task->filepath, md5_hash, sha1_hash, sha256_hash);
    
    printf("📄 Datei: %s\n", task->filepath);
    printf("🔢 MD5:    %s\n", md5_hash);
    printf("🔢 SHA1:   %s\n", sha1_hash);
    printf("🔢 SHA256: %s\n", sha256_hash);

    if (is_virus(md5_hash) || is_virus(sha1_hash) || is_virus(sha256_hash)) {
        printf("⚠️ VIRUS GEFUNDEN: %s ❌\n", task->filepath);
    }

    free(task);
    return NULL;
}

void scan_directory(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) return;
    
    struct dirent *entry;
    struct stat file_stat;
    pthread_t threads[MAX_THREADS];
    int thread_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        
        if (stat(full_path, &file_stat) == 0 && S_ISDIR(file_stat.st_mode)) {
            scan_directory(full_path);  // Rekursion für Verzeichnisse
        } else if (S_ISREG(file_stat.st_mode)) {
            ScanTask *task = malloc(sizeof(ScanTask));
            strncpy(task->filepath, full_path, sizeof(task->filepath));

            pthread_create(&threads[thread_count], NULL, scan_file, task);
            thread_count++;

            if (thread_count >= MAX_THREADS) {
                for (int i = 0; i < thread_count; i++) {
                    pthread_join(threads[i], NULL);
                }
                thread_count = 0;
            }
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    closedir(dir);
}

int main() {
    char start_path[1024];

    printf("🔎 HASH-VIRENSCANNER 🔍\n");
    printf("📂 Gib das zu scannende Verzeichnis ein (z. B. /home/user): ");
    scanf("%1023s", start_path);

    printf("📡 Starte Scan...\n");
    scan_directory(start_path);
    printf("✅ Scan abgeschlossen!\n");

    return 0;
}
