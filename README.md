Input CSV format (for bulk)

Create input.csv like:

primary_email,first_name,last_name,org_unit,personal_email
testuser1@kusoed.edu.np,Test,User1,/Students,test1@gmail.com
testuser2@kusoed.edu.np,Test,User2,/Students,test2@gmail.com

Commands to run
1) Make script executable + protect key
chmod +x create_gw_users.sh
chmod 600 service_account.json

2) Single user create
./create_gw_users.sh \
  --admin "bhandaribbk@kusoed.edu.np" \
  --email "testuser@kusoed.edu.np" \
  --first "Test" \
  --last "User" \
  --ou "/Students" \
  --personal "anamolsapkota.np@gmail.com"

3) Bulk create from CSV
./create_gw_users.sh --admin "bhandaribbk@kusoed.edu.np" --csv "input.csv"
