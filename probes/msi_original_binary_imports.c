/* Only count import DLL families for the selected original MSI Type 1
 * CustomAction Binary. Never load or save the DLL or output original names.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msiquery.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "msi.lib")
#define CAP (16777216u)
#define CATEGORIES 9
static const char *names[CATEGORIES] = {
 "ADVAPI32","MSI","KERNEL32","FUSION","MSCOREE","OLE32","RPCRT4","NTDLL","OTHER"
};
static unsigned int counts[CATEGORIES];
static const char *arch="UNKNOWN";
static HANDLE report=INVALID_HANDLE_VALUE;
static unsigned int rd16(const unsigned char *p) {return (unsigned int)p[0]|((unsigned int)p[1]<<8);}
static unsigned int rd32(const unsigned char *p) {return rd16(p)|(rd16(p+2)<<16);}
static int valid_at(size_t size,size_t off,size_t len){return off<=size && len<=size-off;}
static void put(const char *key,const char *value) {
 char line[180]; DWORD written;
 if(sprintf_s(line,sizeof(line),"SWCOMPAT_BINARY_%s=%s\r\n",key,value)<=0)return;
 if(report!=INVALID_HANDLE_VALUE)WriteFile(report,line,(DWORD)strlen(line),&written,NULL);
 printf("%s",line);
}
static int finish(const char *status) {
 unsigned int i; char num[20];
 put("STATUS",status); put("MACHINE",arch);
 for(i=0;i<CATEGORIES;i++){sprintf_s(num,sizeof(num),"%u",counts[i]);put(names[i],num);}
 if(report!=INVALID_HANDLE_VALUE){FlushFileBuffers(report);CloseHandle(report);}
 return 0;
}
static size_t locate(const unsigned char *b,size_t n,size_t sect,unsigned int ns,unsigned int rva) {
 unsigned int i;
 for(i=0;i<ns;i++){
  size_t p=sect+40u*i; unsigned int va,sz,raw,rawsz,d;
  if(!valid_at(n,p,40))return (size_t)-1;
  va=rd32(b+p+12);sz=rd32(b+p+8);rawsz=rd32(b+p+16);raw=rd32(b+p+20);
  if(sz<rawsz)sz=rawsz;
  if(rva<va || rva-va>=sz)continue;
  d=rva-va;
  if(d>=rawsz || !valid_at(n,(size_t)raw+d,1))return (size_t)-1;
  return (size_t)raw+d;
 }
 return (size_t)-1;
}
static const char *inspect_pe(const unsigned char *b,size_t n) {
 size_t pe,opt,sect,entry; unsigned int ns,opts,magic,irva,i;
 if(!valid_at(n,0,64)||rd16(b)!=0x5a4d)return "NOT_PE";
 pe=rd32(b+0x3c);
 if(!valid_at(n,pe,24)||rd32(b+pe)!=0x4550)return "INVALID_PE";
 switch(rd16(b+pe+4)){
 case IMAGE_FILE_MACHINE_AMD64:arch="AMD64";break;
 case IMAGE_FILE_MACHINE_I386:arch="X86";break;
 case IMAGE_FILE_MACHINE_ARM64:arch="ARM64";break;
 default:arch="OTHER";
 }
 ns=rd16(b+pe+6);opts=rd16(b+pe+20);opt=pe+24;
 if(!ns||ns>96||!valid_at(n,opt,opts))return "INVALID_PE";
 magic=rd16(b+opt);
 if(magic!=0x10b&&magic!=0x20b)return "INVALID_PE";
 if(opts<(magic==0x10b?112u:128u))return "INVALID_PE";
 irva=rd32(b+opt+(magic==0x10b?104u:120u));
 if(!irva)return "PARSED";
 sect=opt+opts;
 if(!valid_at(n,sect,ns*40u))return "INVALID_PE";
 entry=locate(b,n,sect,ns,irva);
 for(i=0;i<256;i++){
  unsigned int rva,k=8; size_t p,e;
  if(!valid_at(n,entry,20))return "INVALID_PE";
  if(!rd32(b+entry)&&!rd32(b+entry+12)&&!rd32(b+entry+16))return "PARSED";
  rva=rd32(b+entry+12);p=locate(b,n,sect,ns,rva);
  if(!valid_at(n,p,1))return "INVALID_PE";
  e=p;while(valid_at(n,e,1)&&b[e]>=32&&b[e]<127&&e-p<127)e++;
  if(!valid_at(n,e,1)||b[e]!=0||e==p)return "INVALID_PE";
  for(k=0;k<CATEGORIES-1;k++){
   const char *match[]={"advapi32.dll","msi.dll","kernel32.dll","fusion.dll",
    "mscoree.dll","ole32.dll","rpcrt4.dll","ntdll.dll"};
   if(!_stricmp((const char *)(b+p),match[k]))break;
  }
  counts[k]++;entry+=20;
 }
 return "INVALID_PE";
}
static int action_input(wchar_t *dst) {
 HANDLE h; unsigned char s[256]; DWORD got=0; size_t i,j;
 h=CreateFileW(L"C:\\windows\\temp\\swcompat_ca_action_private.input",
  GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(h==INVALID_HANDLE_VALUE)return 0;
 if(!ReadFile(h,s,sizeof(s)-1,&got,NULL)){CloseHandle(h);return 0;}
 CloseHandle(h);
 if(!got||got>120)return 0;
 for(i=0;i<got;i++)if(s[i]=='\r'||s[i]=='\n'||s[i]=='\0')break;
 if(!i||i>120)return 0;
 for(j=0;j<i;j++)if(!((s[j]>='A'&&s[j]<='Z')||
  (s[j]>='a'&&s[j]<='z')||(s[j]>='0'&&s[j]<='9')||
  s[j]=='_'||s[j]=='.'))return 0;
 s[i]=0;
 return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,(char*)s,-1,dst,256)>0;
}
int wmain(int argc,wchar_t **argv) {
 wchar_t action[256]={0},source[256]={0};DWORD size=255;
 MSIHANDLE db=0,view=0,param=0,row=0,stream=0;UINT rc;
 const char *state="QUERY_FAILED";unsigned char *data=NULL;size_t used=0;
 if(argc!=4||wcscmp(argv[3],L"--private-file"))return finish("INVALID_ARGUMENT");
 report=CreateFileW(argv[2],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)return finish("REPORT_FAILED");
 if(!action_input(action))return finish("INPUT_FAILED");
 if(MsiOpenDatabaseW(argv[1],MSIDBOPEN_READONLY,&db)!=ERROR_SUCCESS)
  return finish("DATABASE_FAILED");
 rc=MsiDatabaseOpenViewW(db,L"SELECT `Type`, `Source` FROM `CustomAction` WHERE `Action` = ?",&view);
 if(rc!=ERROR_SUCCESS)goto done;
 param=MsiCreateRecord(1);
 if(!param||MsiRecordSetStringW(param,1,action)!=ERROR_SUCCESS)goto done;
 if(MsiViewExecute(view,param)!=ERROR_SUCCESS)goto done;
 rc=MsiViewFetch(view,&row);
 if(rc==ERROR_NO_MORE_ITEMS){state="ACTION_ABSENT";goto done;}
 if(rc!=ERROR_SUCCESS)goto done;
 if((MsiRecordGetInteger(row,1)&63)!=1){state="NOT_DLL_BINARY";goto done;}
 if(MsiRecordGetStringW(row,2,source,&size)!=ERROR_SUCCESS||!size||size>=255)goto done;
 MsiCloseHandle(row);row=0;MsiViewClose(view);MsiCloseHandle(view);view=0;
 MsiCloseHandle(param);param=0;
 if(MsiDatabaseOpenViewW(db,L"SELECT `Data` FROM `Binary` WHERE `Name` = ?",&view)!=ERROR_SUCCESS)goto done;
 param=MsiCreateRecord(1);
 if(!param||MsiRecordSetStringW(param,1,source)!=ERROR_SUCCESS)goto done;
 if(MsiViewExecute(view,param)!=ERROR_SUCCESS)goto done;
 rc=MsiViewFetch(view,&stream);
 if(rc==ERROR_NO_MORE_ITEMS){state="BINARY_ABSENT";goto done;}
 if(rc!=ERROR_SUCCESS)goto done;
 data=(unsigned char*)HeapAlloc(GetProcessHeap(),0,CAP+1u);
 if(!data){state="MEMORY_FAILED";goto done;}
 for(;;){
  DWORD amount=(DWORD)((size_t)(CAP+1u-used)<65536u?CAP+1u-used:65536u);
  rc=MsiRecordReadStream(stream,1,(char*)(data+used),&amount);
  if(rc!=ERROR_SUCCESS){state="STREAM_FAILED";goto done;}
  if(!amount)break;
  used+=amount;
  if(used>CAP){state="STREAM_TOO_LARGE";goto done;}
 }
 state=used?inspect_pe(data,used):"STREAM_EMPTY";
done:
 if(data)HeapFree(GetProcessHeap(),0,data);
 if(stream)MsiCloseHandle(stream);
 if(row)MsiCloseHandle(row);
 if(view){MsiViewClose(view);MsiCloseHandle(view);}
 if(param)MsiCloseHandle(param);
 if(db)MsiCloseHandle(db);
 return finish(state);
}
