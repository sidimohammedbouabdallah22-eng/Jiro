<?php
// Qualification only: snapshot, temporarily change and exactly restore shop URLs.
$input=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
require '/var/www/html/config/config.inc.php';
function snapshot() {
    return ['urls'=>Db::getInstance()->executeS('SELECT * FROM '._DB_PREFIX_.'shop_url ORDER BY id_shop_url'),
        'domain'=>Configuration::get('PS_SHOP_DOMAIN'),'ssl'=>Configuration::get('PS_SHOP_DOMAIN_SSL'),
        'htaccess_base64'=>base64_encode(file_get_contents(_PS_ROOT_DIR_.'/.htaccess'))];
}
function clearDomainCaches() {
    ShopUrl::resetMainDomainCache();
    Tools::clearSmartyCache();
    // This module also caches absolute menu URLs outside Smarty.
    $menu = Module::getInstanceByName('ps_mainmenu');
    if ($menu && $menu->active) $menu->hookActionMetaPageSave([]);
}
if ($input['operation']==='snapshot') { print json_encode(snapshot(),JSON_THROW_ON_ERROR); exit; }
if ($input['operation']==='set') {
    if (!preg_match('/^shop[.]joint[.]test:[0-9]{1,5}$/',$input['domain'])) throw new Exception('invalid_lab_domain');
    foreach(snapshot()['urls'] as $row) {
        $url=new ShopUrl((int)$row['id_shop_url']);$url->domain=$input['domain'];$url->domain_ssl=$input['domain'];
        if(!$url->update()) throw new Exception('domain_update_failed');
    }
    Configuration::updateValue('PS_SHOP_DOMAIN',$input['domain']);Configuration::updateValue('PS_SHOP_DOMAIN_SSL',$input['domain']);
    ShopUrl::resetMainDomainCache();
    if (!Tools::generateHtaccess()) throw new Exception('rewrite_generation_failed');
    clearDomainCaches();
} elseif ($input['operation']==='restore') {
    foreach($input['snapshot']['urls'] as $row) {
        $url=new ShopUrl((int)$row['id_shop_url']);
        foreach(['domain','domain_ssl','physical_uri','virtual_uri','main','active'] as $key) $url->$key=$row[$key];
        if(!$url->update()) throw new Exception('domain_restore_failed');
    }
    Configuration::updateValue('PS_SHOP_DOMAIN',$input['snapshot']['domain']);Configuration::updateValue('PS_SHOP_DOMAIN_SSL',$input['snapshot']['ssl']);
    $original = base64_decode($input['snapshot']['htaccess_base64'], true);
    if ($original === false || file_put_contents(_PS_ROOT_DIR_.'/.htaccess', $original) !== strlen($original)) {
        throw new Exception('rewrite_restore_failed');
    }
    clearDomainCaches();
} else { throw new Exception('invalid_operation'); }
print json_encode(snapshot(),JSON_THROW_ON_ERROR);
