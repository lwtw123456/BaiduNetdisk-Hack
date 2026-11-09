#include "asar_patch.h"

#include <windows.h>

#pragma comment(lib, "advapi32.lib")

#include <algorithm>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include <ctre.hpp>

namespace {

std::wstring module_path(const wchar_t* name)
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&asar_ensure_patched), &module))
        return {};
    std::wstring path(32768, L'\0');
    DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return {};
    path.resize(length);
    size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return {};
    path.resize(slash + 1);
    return path + name;
}

std::string sha256_hex(const std::string& data, size_t off, size_t len)
{
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32];
    DWORD size = 32;
    CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);
    CryptHashData(hash, reinterpret_cast<const BYTE*>(data.data() + off), static_cast<DWORD>(len), 0);
    CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    const char* table = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (BYTE b : digest) {
        out += table[b >> 4];
        out += table[b & 15];
    }
    return out;
}

std::string integrity(const std::string& data)
{
    const size_t block = 4194304;
    std::string out = "{\"algorithm\":\"SHA256\",\"hash\":\"" + sha256_hex(data, 0, data.size()) +
                      "\",\"blockSize\":4194304,\"blocks\":[";
    for (size_t i = 0; i < data.size(); i += block) {
        if (i) out += ',';
        size_t n = data.size() - i < block ? data.size() - i : block;
        out += '"' + sha256_hex(data, i, n) + '"';
    }
    return out + "]}";
}

template <ctll::fixed_string Pattern>
std::vector<std::pair<size_t, size_t>> find_all(std::string_view text)
{
    std::vector<std::pair<size_t, size_t>> hits;
    for (auto m : ctre::search_all<Pattern>(text)) {
        auto v = m.to_view();
        hits.emplace_back(static_cast<size_t>(v.data() - text.data()), v.size());
    }
    return hits;
}

template <ctll::fixed_string Pattern>
bool insert_before(std::string& content, std::string_view literal)
{
    std::vector<std::pair<size_t, size_t>> hits = find_all<Pattern>(content);
    for (auto it = hits.rbegin(); it != hits.rend(); ++it)
        content.insert(it->first, literal);
    return !hits.empty();
}

template <ctll::fixed_string Pattern>
bool replace_all(std::string& content, std::string_view literal)
{
    std::vector<std::pair<size_t, size_t>> hits = find_all<Pattern>(content);
    for (auto it = hits.rbegin(); it != hits.rend(); ++it)
        content.replace(it->first, it->second, literal);
    return !hits.empty();
}

constexpr std::string_view kInject =
    R"x(const _S=`(()=>{if(window.__bdJsonProbe)return;if(!location.href.includes("/disk/mobile/aidraft"))return;window.__bdJsonProbe=1;const O=JSON.parse;JSON.parse=function(t,r){const o=O.call(this,t,r);if(o&&o.login_info){o.login_info.vip_identity=20;o.login_info.vip_level=10}return o}})();`;)x"
    R"x(const _E=require("electron"),_P="/disk/mobile/aidraft";)x"
    R"x(const _A=new Set(),_X=new Set();)x"
    R"x(function _run(w){try{const p=w.executeJavaScript(_S);if(p&&p.catch)p.catch(()=>{})}catch(e){}})x"
    R"x(function _cdp(w){try{const d=w.debugger;if(!d||typeof d.attach!=="function")return;const add=()=>{try{const q=d.sendCommand("Page.enable");if(q&&q.then)q.then(()=>d.sendCommand("Page.addScriptToEvaluateOnNewDocument",{source:_S})).catch(()=>{})}catch(e){}};if(d.isAttached()){add();return}const p=d.attach("1.3");if(p&&p.then)p.then(add,add);else add()}catch(e){}})x"
    R"x(function _hook(w,url,main,exec){try{if(main===false)return;const u=url||(w.getURL?w.getURL():"");if(!u.includes(_P))return;const id=(w.getType?w.getType():"?")+":"+w.id;if(!_A.has(id)){_A.add(id);_cdp(w)}if(exec&&!_X.has(id+"|"+u)){_X.add(id+"|"+u);_run(w)}}catch(e){}})x"
    R"x(_E.app.on("web-contents-created",(e,w)=>{try{w.on("did-start-navigation",(ev,u,i,m)=>_hook(w,u,m,0));w.on("dom-ready",()=>_hook(w,null,null,1));w.on("did-finish-load",()=>_hook(w,null,null,1))}catch(err){}});)x";

bool patch_content(std::string& content)
{
    bool changed =
        insert_before<R"x((let\s+[\w$]+=[\w$]+\.Ch\.normal;return 0===))x">(content, "return 2;");
    changed |= insert_before<R"x(^(/\*! For license information please see main\.js\.LICENSE\.txt \*/))x">(content, kInject);
    changed |= replace_all<R"x(let\s+[\w$]+\s*=\s*new Map[\s\S]{0,450}?YYYY-MM-DD HH:mm:ss["']\)\})x">(content, R"x(return"2099-12-31 23:59:59";})x");
    return changed;
}

struct Fix {
    size_t pos;
    size_t len;
    std::string text;
};

}

extern "C" int asar_ensure_patched(void) {
    try {
        std::wstring src = module_path(L"resources\\core.asar");
        if (src.empty()) return -1;
        std::wstring dst = src + L".patched";
        if (GetFileAttributesW(dst.c_str()) != INVALID_FILE_ATTRIBUTES) return 0;

        std::ifstream in(std::filesystem::path(src), std::ios::binary);
        if (!in) return -1;
        std::string d{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};

        uint32_t jlen = 0;
        std::memcpy(&jlen, d.data() + 12, 4);
        size_t dataStart = 16 + ((jlen + 3) & ~static_cast<size_t>(3));
        std::string json(d.data() + 16, jlen);

        struct Entry {
            size_t size, off;
            size_t sizePos, sizeLen;
            size_t offPos, offLen;
            size_t integPos, integLen;
        };
        std::vector<Entry> entries;
        std::string_view jview = json;
        for (auto m : ctre::search_all<R"x("[^"]+":\{"size":(\d+),"offset":"(\d+)","integrity":(\{[^{}]*\}))x">(jview)) {
            auto sz = m.get<1>().to_view();
            auto off = m.get<2>().to_view();
            auto itg = m.get<3>().to_view();
            auto num = [](std::string_view v) {
                size_t n = 0;
                std::from_chars(v.data(), v.data() + v.size(), n);
                return n;
            };
            entries.push_back({num(sz), num(off),
                static_cast<size_t>(sz.data() - jview.data()), sz.size(),
                static_cast<size_t>(off.data() - jview.data()), off.size(),
                static_cast<size_t>(itg.data() - jview.data()), itg.size()});
        }
        std::sort(entries.begin(), entries.end(),
                  [](const Entry& a, const Entry& b) { return a.off < b.off; });

        size_t total = 0;
        for (const auto& e : entries) total += e.size;
        if (total != d.size() - dataStart) return -5;

        std::vector<Fix> fixes;
        std::string data;
        data.reserve(d.size() - dataStart);
        size_t cursor = 0;
        bool any = false;

        for (const auto& e : entries) {
            std::string content(d.data() + dataStart + e.off, e.size);
            bool changed = patch_content(content);
            if (changed) any = true;

            if (cursor != e.off)
                fixes.push_back({e.offPos, e.offLen, std::to_string(cursor)});
            if (changed) {
                if (content.size() != e.size)
                    fixes.push_back({e.sizePos, e.sizeLen, std::to_string(content.size())});
                fixes.push_back({e.integPos, e.integLen, integrity(content)});
            }

            data.append(content);
            cursor += content.size();
        }
        if (!any) return -2;

        std::sort(fixes.begin(), fixes.end(),
                  [](const Fix& a, const Fix& b) { return a.pos > b.pos; });
        for (const auto& f : fixes) json.replace(f.pos, f.len, f.text);

        uint32_t njlen = static_cast<uint32_t>(json.size());
        size_t aligned = (njlen + 3) & ~static_cast<size_t>(3);
        std::string head(16 + aligned, '\0');
        uint32_t v[4] = {4, static_cast<uint32_t>(8 + aligned),
                         static_cast<uint32_t>(4 + aligned), njlen};
        std::memcpy(head.data(), v, 16);
        std::memcpy(head.data() + 16, json.data(), njlen);

        std::ofstream out(std::filesystem::path(dst), std::ios::binary);
        out.write(head.data(), static_cast<std::streamsize>(head.size()));
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        out.close();
        if (!out) { DeleteFileW(dst.c_str()); return -3; }
        return 1;
    } catch (...) {
        return -4;
    }
}
