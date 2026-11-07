<?php
// Read-only assertions on the pinned lab's real business DB and document bytes.
define('NOLOGIN', 1); define('NOCSRFCHECK', 1); define('NOTOKENRENEWAL', 1);
require '/var/www/html/main.inc.php';
$spec = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
function row($table, $id) {
    global $db;
    if (!is_int($id) || $id <= 0) throw new Exception('invalid_fixture_id');
    $result = $db->query('SELECT * FROM '.MAIN_DB_PREFIX.$table.' WHERE rowid='.$id);
    if (!$result || $db->num_rows($result) !== 1) throw new Exception('business_row_missing');
    return $db->fetch_object($result);
}
function requireFact($condition) { if (!$condition) throw new Exception('business_assertion_failed'); }
$customer = row('societe', $spec['customer']);
$contact = row('socpeople', $spec['contact']);
$order = row('commande', $spec['order']);
$imported = row('societe', $spec['imported']);
requireFact((int) $contact->fk_soc === $spec['customer'] && str_contains($contact->lastname, 'الجزائر'));
requireFact((int) $order->fk_soc === $spec['customer'] && (int) $order->fk_statut === 1 && (float) $order->total_ht === 250.0);
$lines = $db->query('SELECT qty,total_ht FROM '.MAIN_DB_PREFIX.'commandedet WHERE fk_commande='.$spec['order']);
requireFact($lines && $db->num_rows($lines) === 1);
$line = $db->fetch_object($lines); requireFact((float) $line->qty === 2.0 && (float) $line->total_ht === 250.0);
requireFact((int) $imported->client === 1 && (int) $imported->status === 1 && (int) $imported->fournisseur === 0);
requireFact(str_contains($imported->nom, 'الجزائر') && $imported->code_client !== 'auto' && $imported->code_client !== '');
$duplicates = $db->query("SELECT count(*) AS n FROM ".MAIN_DB_PREFIX."societe WHERE email='".$db->escape($imported->email)."'");
requireFact($duplicates && (int) $db->fetch_object($duplicates)->n === 1);
$matches = 0;
foreach (glob($conf->societe->dir_output.'/'.$spec['customer'].'/multipart-*.csv') as $file) {
    if (filesize($file) === $spec['attachment_bytes'] && hash_file('sha256', $file) === $spec['attachment_sha256']) $matches++;
}
requireFact($matches === 1);
$result = ['passed'=>true, 'version'=>DOL_VERSION, 'contact_customer_link'=>true, 'validated_order_total'=>250,
    'order_quantity'=>2, 'native_import_single_committed_customer'=>true, 'native_attachment_exact_bytes'=>true];
if (!empty($spec['capacity_tag'])) {
    $prefix = 'Capacity '.$spec['capacity_tag'].' ';
    requireFact(str_starts_with($customer->note_public, $prefix) && str_ends_with($customer->note_public, str_repeat('a', 16384)));
    $invoice = row('facture', $spec['invoice']);
    $file = $conf->facture->dir_output.'/'.$invoice->ref.'/capacity-'.$spec['capacity_tag'].'.csv';
    requireFact(is_file($file) && hash_file('sha256', $file) === hash('sha256', "capacity document\n".str_repeat('a', 65536)));
    $result['capacity_edits_committed'] = true; $result['capacity_attachment_exact_bytes'] = true;
}
print 'OPENWAF_STATE_RESULT:'.json_encode($result, JSON_THROW_ON_ERROR)."\n";
