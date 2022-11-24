#!/bin/sh
PATH=/etc:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

PGPASSWORD=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^POSTGRES_PASSWORD/{v=t($2)};END{printf "%s\n",v}' ../env)
export PGPASSWORD
pathB=/tmp/
dbUser=postgres
database=test

sudo find $pathB \( -name "*-1[^5].*" -o -name "*-[023]?.*" \) -ctime +61 -delete
cd /tmp/ && sudo -u $dbUser pg_dump -Fc -c $database | gzip > test_$(date "+%Y-%m-%d").sql.gz

unset PGPASSWORD
