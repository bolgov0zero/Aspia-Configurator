import struct, sys
def read_dir(path):
    d=open(path,'rb').read()
    hdr=d[:512]
    ss=1<<struct.unpack('<H',hdr[30:32])[0]
    nfat,dirstart=struct.unpack('<II',hdr[44:52])
    difat=list(struct.unpack('<109I',hdr[76:512]))
    fatsecs=[x for x in difat if x<0xFFFFFFFA]
    nd,ndn=struct.unpack('<II',hdr[68:76]); s=nd
    n=ndn
    while n and s<0xFFFFFFFA:
        sec=d[(s+1)*ss:(s+2)*ss]; ids=struct.unpack('<%dI'%(ss//4),sec); fatsecs+= [x for x in ids[:-1] if x<0xFFFFFFFA]; s=ids[-1]; n-=1
    fat=[]
    for f in fatsecs: fat+=struct.unpack('<%dI'%(ss//4),d[(f+1)*ss:(f+2)*ss])
    buf=b''; s=dirstart
    while s<0xFFFFFFFA:
        buf+=d[(s+1)*ss:(s+2)*ss]; s=fat[s]
    ents=[]
    for i in range(len(buf)//128):
        e=buf[i*128:(i+1)*128]
        nl=struct.unpack('<H',e[64:66])[0]
        name=e[:max(nl-2,0)].decode('utf-16le','replace')
        typ=e[66]; color=e[67]; l,r,c=struct.unpack('<III',e[68:80])
        clsid=e[80:96].hex(); state=struct.unpack('<I',e[96:100])[0]
        ct,mt=struct.unpack('<QQ',e[100:116]); start,size=struct.unpack('<IQ',e[116:128])
        ents.append(dict(i=i,name=name,type=typ,l=l,r=r,c=c,clsid=clsid,state=state,ct=ct,mt=mt,size=size))
    return ents
if __name__=='__main__':
    for e in read_dir(sys.argv[1]):
        if e['type'] in (1,5): print(e['i'],e['type'],repr(e['name']),e['clsid'],hex(e['state']),e['ct'],e['mt'])
