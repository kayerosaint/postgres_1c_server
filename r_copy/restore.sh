#!/bin/sh
PATH=/etc:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

PGPASSWORD=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^POSTGRES_PASSWORD/{v=t($2)};END{printf "%s\n",v}' ../env)
export PGPASSWORD
pathB=/tmp/
dbUser=postgres
database=test

sudo find $pathB \( -name "*-1[^5].*" -o -name "*-[023]?.*" \) -ctime +61 -delete
cd /tmp/ && base_v=$(ls /tmp/ | grep test_2022*.sql.gz) && sudo -u postgres pg_restore -d test -c test.dump | sudo gunzip $base_v

unset PGPASSWORD
