import sys
from pymongo import MongoClient

def main():
    print("Starting local MongoDB scan history purge...")
    try:
        client = MongoClient("mongodb://localhost:27017")
        databases = ["vaultx", "argolock"]
        collections_to_purge = ["scans", "findings", "reports", "raw_findings", "otp_codes"]
        
        for db_name in databases:
            if db_name not in client.list_database_names():
                print(f"Database '{db_name}' does not exist locally. Skipping.")
                continue
                
            db = client[db_name]
            print(f"\nPurging database: {db_name}")
            for coll in collections_to_purge:
                if coll in db.list_collection_names():
                    count = db[coll].count_documents({})
                    if count > 0:
                        db[coll].delete_many({})
                        print(f"  - Cleared {count} documents from collection '{coll}'")
                    else:
                        print(f"  - Collection '{coll}' is already empty")
                else:
                    print(f"  - Collection '{coll}' does not exist")
                    
        print("\nLocal scan histories purged successfully!")
    except Exception as e:
        print("Error connecting to or purging local MongoDB:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
