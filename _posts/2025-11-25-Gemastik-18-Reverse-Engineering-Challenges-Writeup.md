---
layout: post
author: Rafael Putra
title: Gemastik 18 Reverse Engineering Challenges Writeup
---

Gemastik divisi keamanan siber tahun ini diselenggarakan pada 30 Agustus 2025, terdapat beberapa kategori soal, namun saya hanya mengerjakan kategori reverse engineering saja. Terdapat dua soal, soal pertama sudah saya selesaikan tepat waktu, namun untuk soal kedua berhasil saya selesaikan setelah kompetisi berakhir.

## Scripts

Diberikan sebuah file main, untuk menganalisisnya bisa dengan menggunakan perintah `file`.

```
$ file main
main: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=48580e7d341840c4950449c35f723135d1c92d00, for GNU/Linux 3.2.0, stripped
```

Diketahui file ELF 64 bit dengan binary stripped. Ketika dijalankan akan terdapat perintah untuk memasukkan flag.

```
$ ./main
Flag: test
WRONG
```

Selanjutnya melakukan analisis binary tersebut ke IDA, dan decompile pada fungsi main.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int v4; // r8d
  int v5; // r9d
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int result; // eax
  int i; // [rsp+Ch] [rbp-44h]
  int j; // [rsp+10h] [rbp-40h]
  __int64 v14; // [rsp+18h] [rbp-38h]
  _BYTE input[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v16; // [rsp+48h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  sub_44C870((unsigned int)"Flag: ", (_DWORD)argv, (_DWORD)envp, v3, v4, v5);
  sub_44C7A0((unsigned int)"%s", (unsigned int)input, v6, v7, v8, v9);
  if ( sub_401220(input) == 33 )
  {
    for ( i = 0; i <= 1162; ++i )
    {
      if ( byte_54CC00[i] == '*' )
      {
        for ( j = 0; j <= 32; ++j )
          byte_54CC00[i + j] = input[j];
        break;
      }
    }
    v14 = sub_41C650();
    if ( v14 )
    {
      sub_41C730(v14);
      sub_403B70(v14, sub_401F24, 0LL);
      sub_404380(v14, &unk_54CBA0);
      sub_403B70(v14, sub_401F8A, 0LL);
      sub_404380(v14, &unk_54CBC0);
      sub_403B70(v14, sub_401FF0, 0LL);
      sub_404380(v14, &unk_54CBE0);
      if ( (unsigned int)sub_41B6F0(v14, byte_54CC00) || (unsigned int)sub_404A40(v14, 0LL, 0xFFFFFFFFLL, 0LL, 0LL, 0LL) )
      {
        sub_411090(v14);
        result = 1;
      }
      else
      {
        sub_411090(v14);
        result = 0;
      }
    }
    else
    {
      result = 1;
    }
  }
  else
  {
    sub_45C920("WRONG");
    result = 1;
  }
  if ( v16 != __readfsqword(0x28u) )
    sub_492140();
  return result;
}
```

Terlihat bahwa program menerima input flag yang panjangnya harus 33, lalu terdapat operasi looping yang cukup banyak (1162 kali), operasi ini mengakses setiap karakter dari byte_54CC00 apakah sama dengan karakter '*', jika kondisi ini terpenuhi akan dilakukan operasi looping lagi sebanyak 32 kali dan mengakses byte_54CC00 dengan index i+j lalu mencocokkan dengan input pengguna. Dari hasil XREF byte_54CC00, terdapat fungsi sub_402277.

```c
void *sub_402277()
{
  void *result; // rax
  int i; // [rsp+0h] [rbp-30h]
  int j; // [rsp+4h] [rbp-2Ch]
  int k; // [rsp+8h] [rbp-28h]
  int m; // [rsp+Ch] [rbp-24h]

  for ( i = 0; i <= 1162; ++i )
    byte_54CC00[i] = byte_4E9040[i] ^ 0xA0;
  byte_54D08B = 0;
  for ( j = 0; j <= 4; ++j )
    byte_54CBA0[j] = byte_4E94CC[j] ^ 0xA0;
  byte_54CBA5 = 0;
  for ( k = 0; k <= 4; ++k )
    byte_54CBC0[k] = byte_4E94D2[k] ^ 0xA0;
  byte_54CBC5 = 0;
  result = byte_4E94D8;
  for ( m = 0; m <= 4; ++m )
  {
    result = m;
    byte_54CBE0[m] = byte_4E94D8[m] ^ 0xA0;
  }
  byte_54CBE5 = 0;
  return result;
}
```

Dari fungsi tersebut dapat diketahui bahwa terdapat operasi XOR byte_4E9040 dengan 0xA0 sebagai key lalu dimasukkan ke dalam byte_54CC00. Ketika membuka byte_439040 terdapat banyak sekali nilai.

```
byte_4E9040     db 0CFh, 0D0h, 0D3h, 80h, 9Dh, 80h, 0DBh, 82h, 0CAh, 93h
.rodata:00000000004E9040                                         ; DATA XREF: sub_402277+8↑o
.rodata:00000000004E904A                 db 0D3h, 95h, 0CCh, 82h, 8Ch, 80h, 82h, 0CAh, 93h, 0D3h
.rodata:00000000004E9054                 db 95h, 0CCh, 82h, 8Ch, 80h, 82h, 0CDh, 99h, 0CBh, 0D0h
.rodata:00000000004E905E                 db 92h, 82h, 8Ch, 80h, 82h, 0D1h, 0D7h, 0D8h, 97h, 0DAh
...
```

Setelah mengetahui alur programnya, saya perlu mengesktrak semua nilai byte_4E9040 dan melakukan XOR dengan key 0xA0 menggunakan python.

```python
encrypted_data = [
    0xCF, 0xD0, 0xD3, 0x80, 0x9D, 0x80, 0xDB, 0x82, 0xCA, 0x93,
    0xD3, 0x95, 0xCC, 0x82, 0x8C, 0x80, 0x82, 0xCA, 0x93, 0xD3,
    0x95, 0xCC, 0x82, 0x8C, 0x80, 0x82, 0xCD, 0x99, 0xCB, 0xD0,
    0x92, 0x82, 0x8C, 0x80, 0x82, 0xD1, 0xD7, 0xD8, 0x97, 0xDA,
    ...
]

decrypted_bytes = []
for byte in encrypted_data:
    decrypted_byte = byte ^ 0xA0
    decrypted_bytes.append(decrypted_byte)

print("".join(chr(b) for b in decrypted_bytes))
```

Ketika script python tersebut dijalankan, terdapat kode lua.

```lua
ops = {"j3s5l", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "m9kp2", "j3s5l", "j3s5l", "qwx7z", "j3s5l", "j3s5l", "qwx7z", "m9kp2", "j3s5l", "qwx7z", "j3s5l", "m9kp2", "j3s5l", "j3s5l", "m9kp2", "m9kp2", "qwx7z", "j3s5l", "m9kp2", "j3s5l", "m9kp2", "m9kp2", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "qwx7z", "qwx7z"}
k = {143, 193, 38, 93, 97, 13, 149, 22, 102, 163, 38, 84, 55, 157, 130, 12, 65, 133, 194, 3, 9, 162, 198, 41, 77, 20, 55, 76, 17, 192, 207, 104, 163}

pt = "*********************************"
ct = {200, 132, 39, 158, 180, 71, 220, 93, 151, 155, 93, 185, 67, 194, 245, 111, 49, 236, 178, 113, 96, 272, 161, 54, 33, 77, 55, 43, 100, 289, 310, 205, 288}
for i = 1, #pt do
    local op_name = ops[i]
    local key_val = k[i]
    local char_code = string.byte(pt, i)
    local result = 0

    if op_name == "qwx7z" then
        result = qwx7z(char_code, key_val)
    elseif op_name == "m9kp2" then
        result = m9kp2(char_code, key_val)
    elseif op_name == "j3s5l" then
        result = j3s5l(char_code, key_val)
    end

    if result ~= ct[i] then
        print("WRONG")
        os.exit(1)
    end
end

print("CORRECT")
```

Diberikan kumpulan ops yang bernilai j3s5l, m9kp2, dan qwx7z yang akan mengakses ct (ciphertext) dan k (key) per index dengan loop. Berikut adalah analisis ketiga operasi tersebut:

* j3s5l adalah operasi XOR
* qwx7z adalah operasi penjumlahan
* m9kp2 adalah operasi pengurangan

Ketiga operasi itu menggunakan char_code (dari plaintext) dan key_val (dari key). Sehingga proses dekripsi flag dilakukan dengan cara membalikkan ketiga operasi tersebut.

```lua
ops = {"j3s5l", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "m9kp2", "j3s5l", "j3s5l", "qwx7z", "j3s5l", "j3s5l", "qwx7z", "m9kp2", "j3s5l", "qwx7z", "j3s5l", "m9kp2", "j3s5l", "j3s5l", "m9kp2", "m9kp2", "qwx7z", "j3s5l", "m9kp2", "j3s5l", "m9kp2", "m9kp2", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "qwx7z", "qwx7z"}
k = {143, 193, 38, 93, 97, 13, 149, 22, 102, 163, 38, 84, 55, 157, 130, 12, 65, 133, 194, 3, 9, 162, 198, 41, 77, 20, 55, 76, 17, 192, 207, 104, 163}
ct = {200, 132, 39, 158, 180, 71, 220, 93, 151, 155, 93, 185, 67, 194, 245, 111, 49, 236, 178, 113, 96, 272, 161, 54, 33, 77, 55, 43, 100, 289, 310, 205, 288}

pt = ""
for i = 1, #ops do
    local op = ops[i]
    local key = k[i]
    local c = ct[i]
    local char

    if op == "j3s5l" then
        char = c ~ key
    elseif op == "qwx7z" then
        char = c - key
    elseif op == "m9kp2" then
        char = c + key
    end

    pt = pt .. string.char(char)
end

print(pt)
```

Setelah menjalankan script lua tersebut, didapatkan flagnya adalah GEMASTIK18{ez_scripting_language}

## Packs

Diberikan sebuah file Packs.exe, saya menggunakan Detect It Easy untuk menganalisis binary-nya.

<a href="../images/gemastik-18-reverse-engineering-challenges-writeup/die.png" target="_blank">
![](../images/gemastik-18-reverse-engineering-challenges-writeup/die.png)
</a>

Dari output Detect It Easy tersebut, diketahui bahwa binary EXE ini arsitekturnya 32 bit yang diprogram dengan C++ dan terdapat protector themida versi 3.XX. Ketika menjalankan filenya, terdapat perintah untuk memasukkan flag, dan terdapat output "Nope." lalu diakhiri dengan output "Yay!". 

```
E:\ctf\gemastik\rev\Packs>Packs.exe
Flag? test
Wrong length.
Nope.
Nope.
Nope.
Nope.
Nope.
Nope.
...
Yay.
```

Selanjutnya coba masukkan binary tersebut ke IDA.

<a href="../images/gemastik-18-reverse-engineering-challenges-writeup/themida_ida.png" target="_blank">
![](../images/gemastik-18-reverse-engineering-challenges-writeup/themida_ida.png)
</a>

:skull:

Hanya terdapat tiga section di IDA, yaitu, .idata, .themida, dan .boot. Setelah melihat hasil di IDA, saya perlu melakukan unpack terlebih dahulu untuk menemukan fungsi-fungsi penting yang bisa di-decompile. Saya belum pernah mengerjakan soal serupa sehingga saya perlu membaca beberapa artikel terkait themida terlebih dahulu. Saya membuang-buang waktu melakukan debugging dengan x32dbg untuk mengetahui Original Entry Point nya, saya juga harus melakukan bypass anti-debugging menggunakan ScyllaHide, terlalu banyak waktu terbuang di sini untuk mengetahui bagaimana program bekerja. Kemudian mendekati berakhirnya kompetisi, saya mencoba untuk mencari unpacker dengan versi yang sesuai di internet, beberapa unpacker sudah saya coba namun gagal, dan akhirnya saya menemukan unpacker [unlicense](https://github.com/ergrelet/unlicense). Setelah berhasil mengunpack binary, lanjut decompile fungsi main ke IDA.

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edi
  int v4; // edx
  int v5; // eax
  unsigned int v6; // esi
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // ecx
  unsigned int v11; // ecx
  int v12; // edx
  __int128 input; // [esp+Ch] [ebp-34h] BYREF
  int v15; // [esp+1Ch] [ebp-24h]
  unsigned int v16; // [esp+20h] [ebp-20h]
  __int64 v17; // [esp+24h] [ebp-1Ch] BYREF
  int v18; // [esp+2Ch] [ebp-14h]
  int v19; // [esp+3Ch] [ebp-4h]

  v15 = 0;
  input = 0LL;
  v16 = 15;
  LOBYTE(input) = 0;
  v19 = 0;
  sub_401750(std::cout, aFlag);
  sub_401970(std::cin, &input);
  v18 = 0;
  v17 = 0LL;
  sub_4012F0(&v17, &input);
  LOBYTE(v19) = 1;
  v3 = v17;
  v4 = dword_4054BC;
  if ( HIDWORD(v17) - v17 != dword_4054C0 - dword_4054BC )
  {
    v5 = sub_401750(std::cout, aWrongLength);
    std::istream::operator>>(v5, sub_401B70);
    v4 = dword_4054BC;
  }
  v6 = 0;
  if ( dword_4054C0 != v4 )
  {
    do
    {
      if ( *(v3 + v6) != *(v4 + v6) )
      {
        v7 = sub_401750(std::cout, aNope);
        std::istream::operator>>(v7, sub_401B70);
        v4 = dword_4054BC;
      }
      ++v6;
    }
    while ( v6 < dword_4054C0 - v4 );
  }
  v8 = sub_401750(std::cout, aYay);
  std::istream::operator>>(v8, sub_401B70);
  if ( v3 )
  {
    v9 = v3;
    v10 = v18 - v3;
    if ( (v18 - v3) >= 0x1000 )
    {
      v3 = *(v3 - 4);
      v11 = v10 + 35;
      if ( (v9 - v3 - 4) > 0x1F )
LABEL_14:
        invalid_parameter_noinfo_noreturn(v11);
    }
    sub_4021EE(v3);
  }
  if ( v16 > 0xF )
  {
    v12 = input;
    if ( v16 + 1 >= 0x1000 )
    {
      v12 = *(input - 4);
      v11 = v16 + 36;
      if ( (input - v12 - 4) > 0x1F )
        goto LABEL_14;
    }
    sub_4021EE(v12);
  }
  return 0;
}
```

Dari hasil dekompilasi telah ditemukan alur program yang sesuai. Program menerima input pengguna, lalu input itu diolah di fungsi sub_4012F0 dan menyimpannya ke v17, hasil transformasi input itu nantinya dicek apakah panjangnya sama seperti dword_4054C0 - dword_4054BC, jika sama maka akan dilakukan operasi looping untuk membandingkan v17 dengan dword_4054BC. Maka untuk memenuhi kondisi ini, perlu decompile fungsi transformasi sub_4012F0.

```cpp
_DWORD *__fastcall sub_4012F0(_DWORD *a1, _DWORD *a2)
{
  int v4; // esi
  unsigned int v5; // eax
  unsigned int i; // edx
  _DWORD *v7; // eax
  int v8; // edx
  int v9; // eax
  unsigned int v10; // eax
  char v11; // cl
  int v13; // [esp+8h] [ebp-4h]
  _BYTE *v14; // [esp+8h] [ebp-4h]

  *a1 = 0LL;
  a1[2] = 0;
  v13 = a2[4];
  *a1 = 0;
  a1[1] = 0;
  a1[2] = 0;
  if ( v13 )
  {
    sub_401E10(v13);
    v4 = *a1;
    j_memset(*a1, 0, v13);
    a1[1] = v4 + v13;
  }
  v5 = a2[4];
  for ( i = 0; i < v5; v5 = a2[4] )
  {
    v7 = a2;
    if ( a2[5] > 0xFu )
      v7 = *a2;
    *(i + *a1) = *(v7 + i);
    ++i;
  }
  v8 = 0;
  if ( v5 )
  {
    do
    {
      v14 = (v8 + *a1);
      if ( v8 <= 10 )
        v9 = ((2 * (*v14 - v8)) | ((*v14 - v8) >> 7)) - 5;
      else
        v9 = ((16 * (*v14 - v8 + 1)) | ((*v14 - v8 + 1) >> 4)) ^ 0x7A;
      if ( (v8 & 1) == 0 )
      {
        v10 = ((4 * ~v9) | (~v9 >> 6));
        v9 = (16 * v10) | (v10 >> 4);
      }
      if ( v8 == 4 )
        v11 = 74 - v9;
      else
        v11 = v8 + v9 + 45;
      ++v8;
      *v14 = v11;
    }
    while ( v8 < a2[4] );
  }
  return a1;
}
```

sub_4012F0 berfungsi untuk mentransformasikan input pengguna, berikut adalah analisisnya:

* Saat index <= 10, terdapat operasi rotate left v9 = ((2 * (*v14 - v8)) | ((*v14 - v8) >> 7)) - 5
* Saat index > 10, terdapat operasi rotate right v9 = ((16 * (*v14 - v8 + 1)) | ((*v14 - v8 + 1) >> 4)) ^ 0x7A
* Saat v8 & 1 == 0 (genap), terdapat operasi negasi, shifting, dan rotasi
* Saat index == 4, maka nilai output = 74 - v9
* Saat index != 4, maka nilai output = v8 + v9 + 45

Maka untuk menyelesaikan challenge ini perlu melakukan pembalikan dari fungsi transformasinya. Sekarang saya perlu mencari nilai dari dword_4054BC dengan XREF.

```
mov     dword ptr [esp+0Ch], 0A7CAB1CAh
.text:00401022                 lea     ecx, [esp+0Ch]
.text:00401026                 mov     dword ptr [esp+10h], 0B7D2CBB1h
.text:0040102E                 mov     eax, edi
.text:00401030                 mov     dword ptr [esp+14h], 26BF8FE1h
.text:00401038                 mov     dword ptr [esp+18h], 0DB27A632h
.text:00401040                 mov     dword ptr [esp+1Ch], 98DCCC2Eh
.text:00401048                 mov     dword ptr [esp+20h], 35C5161h
.text:00401050                 mov     dword ptr [esp+24h], 4784E485h
.text:00401058                 mov     dword ptr [esp+28h], 75B345B9h
.text:00401060                 mov     dword ptr [esp+2Ch], 2EABFC76h
.text:00401068                 mov     dword ptr [esp+30h], 0B26C1B72h
.text:00401070                 mov     dword ptr [esp+34h], 42C394AAh
.text:00401078                 mov     dword ptr [esp+38h], 0EADC23C5h
.text:00401080                 sub     eax, ecx
.text:00401082                 jz      short loc_4010AE
.text:00401084                 push    eax
.text:00401085                 mov     ecx, offset dword_4054BC
.text:0040108A                 call    sub_401E10
.text:0040108F                 mov     esi, ds:dword_4054BC
.text:00401095                 lea     eax, [esp+0Ch]
.text:00401099                 sub     edi, eax
.text:0040109B                 push    edi
.text:0040109C                 push    eax
.text:0040109D                 push    esi
.text:0040109E                 call    j_memcpy
.text:004010A3                 lea     eax, [edi+esi]
.text:004010A6                 add     esp, 0Ch
.text:004010A9                 mov     ds:dword_4054C0, eax
```

Semua informasi sudah didapat, selanjutnya buat script python untuk mengekstrak semua nilai dword_4054BC, dan membalikkan logika transformasinya.

```python
def ror8(val, r_bits):
    return ((val & 0xFF) >> (r_bits % 8)) | (((val & 0xFF) << (8 - (r_bits % 8))) & 0xFF)

def rol8(val, r_bits):
    return (((val << (r_bits % 8)) & 0xFF) | ((val & 0xFF) >> (8 - (r_bits % 8))))

ciphertext = [
    0xCA, 0xB1, 0xCA, 0xA7, 0xB1, 0xCB, 0xD2, 0xB7, 0xE1, 0x8F, 0xBF, 0x26,
    0x32, 0xA6, 0x27, 0xDB, 0x2E, 0xCC, 0xDC, 0x98, 0x61, 0x51, 0x5C, 0x03,
    0x85, 0xE4, 0x84, 0x47, 0xB9, 0x45, 0xB3, 0x75, 0x76, 0xFC, 0xAB, 0x2E,
    0x72, 0x1B, 0x6C, 0xB2, 0xAA, 0x94, 0xC3, 0x42, 0xC5, 0x23, 0xDC, 0xEA
]

plaintext = []

for i, c_byte in enumerate(ciphertext):
    if i == 4:
        v9_transformed = 74 - c_byte
    else:
        v9_transformed = c_byte - i - 45

    v9_before_even = v9_transformed

    if (i % 2) == 0:
        v10 = rol8(v9_transformed, 4)
        v9_before_even = ~ror8(v10, 2) & 0xFF

    if i <= 10:
        p_byte = ror8(v9_before_even + 5, 1) + i
    else:
        p_byte = ror8(v9_before_even ^ 0x7A, 4) + i - 1

    plaintext.append(chr(p_byte & 0xFF))

print("Flag:", "".join(plaintext))
```

Setelah script tersebut dijalankan, didapatkan flagnya GEMASTIK18{S1mpl3_P4ck3r_f0r_4_S1mpl3_Ch4ll3nge}