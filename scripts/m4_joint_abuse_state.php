<?php
// Owned-lab read-only customer snapshot. Persist hashes, never row contents.
define('NOLOGIN',1);define('NOCSRFCHECK',1);define('NOTOKENRENEWAL',1);
require '/var/www/html/main.inc.php';
$result=$db->query('SELECT * FROM '.MAIN_DB_PREFIX.'societe ORDER BY rowid');
if(!$result)throw new Exception('customer_snapshot_query_failed');
$hash=hash_init('sha256');$count=0;
while($row=$db->fetch_object($result)) {
    hash_update($hash,json_encode($row,JSON_THROW_ON_ERROR)."\n");$count++;
}
echo 'OPENWAF_ABUSE_STATE:'.json_encode(['customers'=>$count,'sha256'=>hash_final($hash)],JSON_THROW_ON_ERROR);
