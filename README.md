# Sehatpedia

Situs edukasi kesehatan dengan direktori kondisi umum, akun pengguna, dan chat AI OpenAI yang disajikan melalui backend Node.js. Data akun disimpan lokal di `data/users.json`; kata sandi disimpan sebagai hash scrypt, bukan teks biasa. Sesi masuk disimpan di memori server dan berakhir saat server dimulai ulang. Chat tidak disimpan oleh aplikasi ini. Pesan chat dikirim ke OpenAI untuk menghasilkan jawaban; jangan masukkan nama lengkap, NIK, alamat, atau informasi pribadi.

## Menjalankan

Perlu Node.js 18 atau lebih baru. Akun dapat didaftarkan secara lokal. API key OpenAI hanya diperlukan untuk fitur chat AI.

PowerShell:

```powershell
$env:OPENAI_API_KEY = "isi-api-key-anda"
npm start
```

Command Prompt:

```cmd
set OPENAI_API_KEY=isi-api-key-anda
npm start
```

Buka `http://127.0.0.1:3000` untuk mendaftar atau masuk. Opsional: atur `OPENAI_MODEL` atau `PORT` sebelum menjalankan server. Untuk deploy melalui HTTPS, atur `COOKIE_SECURE=true` dan `PUBLIC_ORIGIN` ke origin situs. API key tidak boleh dimasukkan ke `index.html`, dibagikan, atau di-commit ke repositori.

Penyimpanan akun berbasis file dan sesi dalam memori ini ditujukan untuk pemakaian lokal/demo, bukan sistem autentikasi produksi atau penggunaan bersama banyak pengguna. Sebelum dipublikasikan, gunakan database dan penyimpanan sesi yang terkelola, HTTPS, serta mekanisme pencadangan yang sesuai.

## Batasan kesehatan

Asisten hanya untuk edukasi umum, bukan diagnosis, resep, atau layanan darurat. Jawabannya dapat keliru. Untuk keluhan pribadi, hubungi tenaga kesehatan; untuk keadaan gawat, pergi ke IGD atau hubungi layanan darurat setempat.
