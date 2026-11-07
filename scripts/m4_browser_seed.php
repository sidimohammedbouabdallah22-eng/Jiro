<?php
$input = json_decode(stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
if ($input['app'] === 'dolibarr') {
    define('NOLOGIN', 1); define('NOCSRFCHECK', 1); define('NOTOKENRENEWAL', 1);
    require '/var/www/html/main.inc.php';
    $result = [];
    foreach (['lab-admin', 'lab-reader'] as $login) {
        $account = new User($db);
        if ($account->fetch('', $login) <= 0) throw new Exception('account_missing');
        $result[$login] = (int)$account->id;
    }
    echo 'OPENWAF_BROWSER_SEED:'.json_encode($result, JSON_THROW_ON_ERROR);
    exit;
}
require '/var/www/html/config/config.inc.php';
if (!preg_match('/^nat-[a-f0-9]{8}@example[.]invalid$/', $input['email'])) throw new Exception('invalid_lab_email');
$id = (int)Customer::customerExists($input['email'], true);
if (!$id) {
    $customer = new Customer();
    $customer->firstname = 'NAT'; $customer->lastname = 'Qualification';
    $customer->email = $input['email']; $customer->passwd = Tools::hash($input['password']);
    $customer->active = 1; $customer->id_default_group = 3;
    if (!$customer->add()) throw new Exception('customer_creation_failed');
    $id = (int)$customer->id;
    $address = new Address(); $address->id_customer = $id; $address->alias = 'NAT lab';
    $address->firstname = 'NAT'; $address->lastname = 'Qualification';
    $address->address1 = '12 Example Street'; $address->city = 'Paris'; $address->postcode = '75001';
    $address->id_country = (int)Country::getByIso('FR'); $address->phone = '0100000000';
    if (!$address->add()) throw new Exception('address_creation_failed');
}
echo 'OPENWAF_BROWSER_SEED:'.json_encode(['customer_id'=>$id], JSON_THROW_ON_ERROR);
