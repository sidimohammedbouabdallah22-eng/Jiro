<?php
// Hash protected business rows without exporting their contents.
require '/var/www/html/config/config.inc.php';
$tables=['customer'=>'id_customer','address'=>'id_address','orders'=>'id_order',
         'order_detail'=>'id_order_detail','cart'=>'id_cart',
         'cart_product'=>'id_cart,id_product,id_product_attribute,id_address_delivery'];
$result=[];
foreach($tables as $table=>$order) {
    $rows=Db::getInstance()->executeS('SELECT * FROM '._DB_PREFIX_.$table.' ORDER BY '.$order);
    if($rows===false)throw new Exception('protected_state_query_failed');
    $hash=hash_init('sha256');
    foreach($rows as $row)hash_update($hash,json_encode($row,JSON_THROW_ON_ERROR)."\n");
    $result[$table]=['rows'=>count($rows),'sha256'=>hash_final($hash)];
}
echo 'OPENWAF_STORE_STATE:'.json_encode($result,JSON_THROW_ON_ERROR);
