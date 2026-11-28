// Self-authored synthetic D3D11/DXGI control, no vendor content.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <dwmapi.h>
#include <wrl/client.h>
#include <cstdio>
#include <cstdlib>
using Microsoft::WRL::ComPtr;
static void report(const char *driver,const char *stage,HRESULT hr) {
    printf("SWCOMPAT_D3D_%s_%s=%08lX\n",driver,stage,static_cast<unsigned long>(static_cast<DWORD>(hr)));
    fflush(stdout);
}
static LRESULT CALLBACK wndproc(HWND w,UINT m,WPARAM a,LPARAM b){return DefWindowProcW(w,m,a,b);}
static void pump() {
    MSG m={}; for(int i=0;i<1000 && PeekMessageW(&m,nullptr,0,0,PM_REMOVE);++i){
        TranslateMessage(&m); DispatchMessageW(&m);
    }
}
static bool channel_matches(int x,int y){return std::abs(x-y)<=2;}
static void run(const char *name,D3D_DRIVER_TYPE driver,HWND w){
    ComPtr<ID3D11Device> dev; ComPtr<ID3D11DeviceContext> ctx; ComPtr<IDXGISwapChain> swap;
    DXGI_SWAP_CHAIN_DESC sd={};
    sd.BufferDesc.Width=320; sd.BufferDesc.Height=240; sd.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.SampleDesc.Count=1; sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount=2; sd.OutputWindow=w; sd.Windowed=TRUE; sd.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
    HRESULT h=D3D11CreateDeviceAndSwapChain(nullptr,driver,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&sd,&swap,&dev,nullptr,&ctx);
    report(name,"CREATE",h); if(FAILED(h)||!dev||!ctx||!swap)return;
    ComPtr<ID3D11Texture2D> back,staging; ComPtr<ID3D11RenderTargetView> view;
    h=swap->GetBuffer(0,IID_PPV_ARGS(&back));
    if(SUCCEEDED(h))h=dev->CreateRenderTargetView(back.Get(),nullptr,&view);
    report(name,"TARGET",h); if(FAILED(h)||!view)return;
    D3D11_TEXTURE2D_DESC d={};back->GetDesc(&d);d.Usage=D3D11_USAGE_STAGING;
    d.BindFlags=0;d.CPUAccessFlags=D3D11_CPU_ACCESS_READ;d.MiscFlags=0;
    h=dev->CreateTexture2D(&d,nullptr,&staging);report(name,"STAGING",h);if(FAILED(h)||!staging)return;
    const float colors[2][4]={{19.f/255,83.f/255,147.f/255,1.f},{29.f/255,205.f/255,91.f/255,1.f}};
    const int expected[2][3]={{19,83,147},{29,205,91}};
    bool match=true;
    for(int i=0;i<2;++i){
        ctx->ClearRenderTargetView(view.Get(),colors[i]);ctx->CopyResource(staging.Get(),back.Get());
        D3D11_MAPPED_SUBRESOURCE map={};h=ctx->Map(staging.Get(),0,D3D11_MAP_READ,0,&map);
        if(FAILED(h)){match=false;break;}
        if(!map.pData||map.RowPitch<320*4)match=false;
        else{auto p=static_cast<const BYTE*>(map.pData)+120*map.RowPitch+160*4;
             match=match&&channel_matches(p[0],expected[i][0])&&channel_matches(p[1],expected[i][1])&&channel_matches(p[2],expected[i][2])&&p[3]>=253;}
        ctx->Unmap(staging.Get(),0);
    }
    report(name,"MAP",h);printf("SWCOMPAT_D3D_%s_TEXTURE=%s\n",name,match?"MATCH":"NOT_VERIFIED");fflush(stdout);
    ctx->ClearRenderTargetView(view.Get(),colors[1]);h=swap->Present(1,0);report(name,"PRESENT",h);
    for(int i=0;i<20;++i){pump();Sleep(25);}
    HDC dc=GetDC(w);COLORREF p=dc?GetPixel(dc,160,120):CLR_INVALID;if(dc)ReleaseDC(w,dc);
    printf("SWCOMPAT_D3D_%s_WINDOW=%s\n",name,p==CLR_INVALID?"API_FAILED":
        (channel_matches(GetRValue(p),29)&&channel_matches(GetGValue(p),205)&&channel_matches(GetBValue(p),91))?"MATCH":"NO_MATCH");
    report(name,"DEVICE_REMOVED",dev->GetDeviceRemovedReason());ctx->ClearState();ctx->Flush();
}
int main(){
    WNDCLASSW wc={};wc.lpfnWndProc=wndproc;wc.hInstance=GetModuleHandleW(nullptr);wc.lpszClassName=L"SWCompatSyntheticD3D11";
    if(!RegisterClassW(&wc))return 2;
    HWND w=CreateWindowExW(0,wc.lpszClassName,L"Synthetic D3D11 control",WS_OVERLAPPEDWINDOW,100,100,360,300,nullptr,nullptr,wc.hInstance,nullptr);
    if(!w)return 2;ShowWindow(w,SW_SHOWNORMAL);UpdateWindow(w);pump();
    BOOL enabled=FALSE;HRESULT h=DwmIsCompositionEnabled(&enabled);report("DWM","QUERY",h);
    printf("SWCOMPAT_D3D_DWM_ENABLED=%s\n",FAILED(h)?"UNKNOWN":enabled?"YES":"NO");
    run("HARDWARE",D3D_DRIVER_TYPE_HARDWARE,w);run("WARP",D3D_DRIVER_TYPE_WARP,w);
    DestroyWindow(w);puts("SWCOMPAT_D3D_PROBE=COMPLETE");return 0;
}
