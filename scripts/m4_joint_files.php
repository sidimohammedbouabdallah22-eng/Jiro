<?php
define('NOLOGIN',1);define('NOCSRFCHECK',1);define('NOTOKENRENEWAL',1);
require '/var/www/html/main.inc.php';
$spec=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
$count=0;$bytes=0;$refused=0;$ambiguous=[];
foreach($spec['files'] as $file) {
    if(!preg_match('/^[a-zA-Z0-9_.-]+$/',$file['name']) || !preg_match('/^[a-zA-Z0-9_-]+$/',$file['ref'])) throw new Exception('invalid_lab_filename');
    $path=($file['kind']==='native'?$conf->societe->dir_output:$conf->facture->dir_output).'/'.$file['ref'].'/'.$file['name'];
    if (!empty($file['commit_unknown'])) {
        $exists=is_file($path);
        if ($exists && (filesize($path)!==$file['bytes'] || hash_file('sha256',$path)!==$file['sha256'])) throw new Exception('ambiguous_file_bytes_differ');
        $ambiguous[]=['name'=>$file['name'],'committed'=>$exists,'bytes'=>$exists?filesize($path):0,'sha256'=>$exists?hash_file('sha256',$path):null];
        if($exists){$count++;$bytes+=$file['bytes'];}else{$refused++;}
        continue;
    }
    if(!$file['committed']) {if(file_exists($path))throw new Exception('refused_file_was_committed');$refused++;continue;}
    if(!is_file($path) || filesize($path)!==$file['bytes'] || hash_file('sha256',$path)!==$file['sha256']) throw new Exception('file_bytes_differ');
    $count++;$bytes+=$file['bytes'];
}
$result=['passed'=>true,'files'=>$count,'bytes'=>$bytes,'refused_files_absent'=>$refused];
if ($ambiguous) $result['ambiguous_files']=$ambiguous;
echo 'OPENWAF_FILES:'.json_encode($result,JSON_THROW_ON_ERROR);
