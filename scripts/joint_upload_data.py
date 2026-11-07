"""Public deterministic attachment fixtures; sizes describe decoded file bytes."""
import csv
import io


def upload_content(kind='uniform'):
    size=700<<10
    if kind=='uniform':
        prefix=b'OpenWAF sustained upload\n'
        return prefix+b'a'*(size-len(prefix))
    if kind!='mixed-csv':raise ValueError('unknown attachment fixture')
    def line(values):
        stream=io.StringIO(newline='');csv.writer(stream,lineterminator='\r\n').writerow(values)
        return stream.getvalue().encode('utf-8')
    chunks=[line(['customer','description','currency','amount','date'])];total=len(chunks[0]);index=0
    names=['Acme société','مؤسسة الاختبار','株式会社テスト',"O'Brien Supplies"]
    descriptions=['Bolt M8, zinc plated','KIT "A", 24 mm','مرحبا – café','Delivery\r\nsecond line']
    while True:
        row=line([names[index%4],descriptions[(index//4)%4],'EUR',str(index%10000)+'.95','2026-11-06'])
        if total+len(row)>size-128:break
        chunks.append(row);total+=len(row);index+=1
    empty=line(['padding','','EUR','0.00','2026-11-06'])
    pad=size-total-len(empty);assert pad>=0
    chunks.append(line(['padding','a'*pad,'EUR','0.00','2026-11-06']))
    result=b''.join(chunks);assert len(result)==size
    return result
