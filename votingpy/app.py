from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
import mysql.connector
import hashlib
import random
import requests
from datetime import datetime
import csv
import io
import base64
import os
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Konfigurasi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'votinguser'
app.config['MYSQL_PASSWORD'] = 'votingpass'
app.config['MYSQL_DB'] = 'voting'

# Custom flash function dengan tipe
def flash_message(message, category='info'):
    """Custom flash message dengan kategori"""
    if not session.get('_flashes'):
        session['_flashes'] = []
    session['_flashes'].append({'message': message, 'category': category})

# Override flash default
def flash(message, category='info'):
    flash_message(message, category)

# Context processor untuk flash messages
@app.context_processor
def inject_flash_messages():
    messages = []
    if session.get('_flashes'):
        messages = session.pop('_flashes')
    return dict(flash_messages=messages)

# Caesar Cipher Encryption/Decryption
CAESAR_SHIFT = 3  # Jumlah pergeseran default untuk Caesar Cipher

def caesar_encrypt(text, shift=CAESAR_SHIFT):
    """Enkripsi menggunakan Caesar Cipher dengan shift tertentu"""
    encrypted = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        elif char.isdigit():
            encrypted += chr((ord(char) - ord('0') + shift) % 10 + ord('0'))
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(text, shift=CAESAR_SHIFT):
    """Dekripsi menggunakan Caesar Cipher dengan shift tertentu"""
    decrypted = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        elif char.isdigit():
            decrypted += chr((ord(char) - ord('0') - shift) % 10 + ord('0'))
        else:
            decrypted += char
    return decrypted

def encrypt_data(data, shift=CAESAR_SHIFT):
    """Enkripsi data menggunakan Caesar Cipher dengan shift tertentu"""
    encrypted_text = caesar_encrypt(data, shift)
    # Tambahkan metadata shift ke dalam data
    metadata = f"SHIFT:{shift}:"
    return base64.urlsafe_b64encode((metadata + encrypted_text).encode()).decode()

def decrypt_data(encrypted_data, provided_shift=None):
    """Dekripsi data menggunakan Caesar Cipher"""
    try:
        # Decode dari base64 terlebih dahulu
        decoded_data = base64.urlsafe_b64decode(encrypted_data).decode()
        
        # Cek apakah ada metadata shift di awal data
        if decoded_data.startswith("SHIFT:"):
            parts = decoded_data.split(":", 2)
            if len(parts) >= 3:
                stored_shift = int(parts[1])
                encrypted_text = parts[2]
                
                # Gunakan shift yang disediakan atau yang tersimpan
                if provided_shift is not None:
                    shift_to_use = provided_shift
                else:
                    shift_to_use = stored_shift
                
                return caesar_decrypt(encrypted_text, shift_to_use)
        
        # Jika tidak ada metadata, gunakan shift default atau yang disediakan
        shift_to_use = provided_shift if provided_shift is not None else CAESAR_SHIFT
        return caesar_decrypt(decoded_data, shift_to_use)
        
    except:
        return None

def get_db_connection():
    """Membuat koneksi database"""
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )

def fetch_all(query, params=None):
    """Execute SELECT query and return all results"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, params or ())
        result = cursor.fetchall()
        return result
    except Exception as e:
        print(f"Database fetch error: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def execute_query(query, params=None):
    """Execute INSERT/UPDATE/DELETE query"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Database execute error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_admin_password():
    """
    Ambil password admin dari database
    """
    try:
        result = fetch_all("SELECT password FROM admin WHERE username = 'admin' LIMIT 1")
        if result:
            return result[0]['password']
        return None
    except Exception as e:
        print(f"Error getting admin password: {e}")
        return None

# ==================== ROUTES SEDERHANA ====================

@app.route('/admin/hasil')
def hasil():
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    try:
        results = fetch_all('''
            SELECT pilihan, COUNT(*) as total 
            FROM hasil_voting 
            GROUP BY pilihan 
            ORDER BY total DESC
        ''')
        
        result_total = fetch_all('SELECT COUNT(*) as total FROM hasil_voting')
        total_votes = result_total[0]['total'] if result_total else 0
    except Exception as e:
        flash('Error mengambil hasil voting!')
        results = []
        total_votes = 0
        print(f"Hasil voting error: {e}")
    
    return render_template('download_hasil.html', results=results, total_votes=total_votes)

@app.route('/admin/download-hasil', methods=['GET', 'POST'])
def download_hasil():
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password_input = request.form.get('password')
        shift_input = request.form.get('shift', str(CAESAR_SHIFT))
        
        # Validasi input shift
        try:
            shift_value = int(shift_input)
            if shift_value < 1 or shift_value > 25:
                flash('Shift harus antara 1 dan 25!', 'error')
                return redirect(url_for('hasil'))
        except ValueError:
            flash('Shift harus berupa angka!', 'error')
            return redirect(url_for('hasil'))
        
        admin_password = get_admin_password()
        
        if not admin_password:
            flash('Error: Password admin tidak ditemukan!', 'error')
            return redirect(url_for('admin_dashboard'))
        
        password_input_md5 = hashlib.md5(password_input.encode()).hexdigest()
        
        try:
            results = fetch_all('''
                SELECT pilihan, COUNT(*) as total 
                FROM hasil_voting 
                GROUP BY pilihan 
                ORDER BY total DESC
            ''')
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Pilihan', 'Total Suara'])
            for result in results:
                writer.writerow([result['pilihan'], result['total']])
            
            csv_data = output.getvalue()
            output.close()
            
            # VERIFIKASI 2FA: PASSWORD + SHIFT HARUS BENAR
            password_correct = (password_input_md5 == admin_password)
            shift_correct = (shift_value == CAESAR_SHIFT)  # Shift harus sama dengan sistem
            
            if password_correct and shift_correct:
                # Keduanya benar - file CSV normal
                response = make_response(csv_data)
                response.headers["Content-Disposition"] = "attachment; filename=hasil_voting.csv"
                response.headers["Content-type"] = "text/csv"
                flash('Download berhasil! Password dan shift benar.', 'success')
                return response
            else:
                # Salah satu atau kedua-duanya salah - file terenkripsi
                # Enkripsi dengan shift yang dimasukkan user (bukan sistem)
                encrypted_data = encrypt_data(csv_data, shift_value)
                response = make_response(encrypted_data)
                response.headers["Content-Disposition"] = "attachment; filename=hasil_voting_encrypted.txt"
                response.headers["Content-type"] = "text/plain"
                
                # Simpan shift yang digunakan di session untuk referensi
                session['last_encryption_shift'] = shift_value
                
                # Beri pesan berbeda berdasarkan kesalahan
                if not password_correct and not shift_correct:
                    flash('Password salah dan shift tidak sesuai sistem! File terenkripsi.', 'warning')
                elif not password_correct:
                    flash('Password salah! File terenkripsi.', 'warning')
                elif not shift_correct:
                    flash(f'Shift tidak sesuai sistem (harus {CAESAR_SHIFT})! File terenkripsi dengan shift={shift_value}.', 'warning')
                
                return response
                
        except Exception as e:
            flash('Error download hasil!', 'error')
            print(f"Download hasil error: {e}")
    
    return render_template('download_hasil.html', default_shift=CAESAR_SHIFT)

@app.route('/admin/dekripsi-hasil', methods=['GET', 'POST'])
def dekripsi_hasil():
    """Halaman untuk mendekripsi file hasil voting"""
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'encrypted_file' not in request.files:
            flash('Tidak ada file yang diupload!', 'error')
            return redirect(url_for('dekripsi_hasil'))
        
        file = request.files['encrypted_file']
        shift_input = request.form.get('shift', str(CAESAR_SHIFT))
        
        if file.filename == '':
            flash('Tidak ada file yang dipilih!', 'error')
            return redirect(url_for('dekripsi_hasil'))
        
        try:
            shift_value = int(shift_input)
        except ValueError:
            flash('Shift harus berupa angka!', 'error')
            return redirect(url_for('dekripsi_hasil'))
        
        try:
            # Baca file terenkripsi
            encrypted_content = file.read().decode('utf-8')
            
            # Coba dekripsi
            decrypted_content = decrypt_data(encrypted_content, shift_value)
            
            if decrypted_content is None:
                flash(f'Gagal mendekripsi dengan shift={shift_value}. Coba shift yang berbeda.', 'error')
                return redirect(url_for('dekripsi_hasil'))
            
            # Cek apakah hasil dekripsi valid (mengandung header CSV)
            if 'Pilihan' in decrypted_content and 'Total Suara' in decrypted_content:
                response = make_response(decrypted_content)
                response.headers["Content-Disposition"] = "attachment; filename=hasil_voting_dekripsi.csv"
                response.headers["Content-type"] = "text/csv"
                
                # Cek apakah shift yang digunakan benar (sama dengan sistem)
                if shift_value == CAESAR_SHIFT:
                    flash(f'Dekripsi berhasil! Shift {shift_value} sesuai sistem.', 'success')
                else:
                    flash(f'Dekripsi berhasil dengan shift={shift_value}, tapi tidak sesuai sistem (harus {CAESAR_SHIFT}).', 'warning')
                
                return response
            else:
                flash(f'Dekripsi dengan shift={shift_value} tidak menghasilkan file CSV yang valid.', 'error')
                return redirect(url_for('dekripsi_hasil'))
                
        except Exception as e:
            flash(f'Error saat mendekripsi file: {str(e)}', 'error')
            print(f"Dekripsi file error: {e}")
            return redirect(url_for('dekripsi_hasil'))
    
    last_shift = session.get('last_encryption_shift', CAESAR_SHIFT)
    return render_template('dekripsi_hasil.html', default_shift=last_shift)

@app.route('/admin/lihat-shift')
def lihat_shift():
    """Halaman untuk melihat shift sistem (hanya untuk debugging/testing)"""
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    # Hanya tampilkan shift sistem jika dalam mode debug
    if app.debug:
        return f"Shift sistem Caesar Cipher: {CAESAR_SHIFT}"
    else:
        flash('Akses tidak diizinkan di mode produksi!', 'error')
        return redirect(url_for('admin_dashboard'))

# ==================== ROUTES VOTING ====================

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    """Halaman voting"""
    if not session.get('voter_allowed'):
        flash('Anda tidak memiliki akses untuk voting!', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        id_kandidat = request.form.get('id_kandidat')
        
        try:
            # Dapatkan nama kandidat
            result = fetch_all('SELECT nama FROM kandidat WHERE id = %s', (id_kandidat,))
            
            if result:
                kandidat = result[0]
                # Simpan hasil voting
                execute_query('INSERT INTO hasil_voting (pilihan) VALUES (%s)', (kandidat['nama'],))
                
                session.clear()
                flash('Vote berhasil! Terima kasih telah berpartisipasi.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Kandidat tidak valid!', 'error')
        except Exception as e:
            flash('Error saat melakukan voting!', 'error')
            print(f"Submit vote error: {e}")
    
    try:
        kandidat_list = fetch_all('SELECT * FROM kandidat')
        return render_template('vote.html', kandidat_list=kandidat_list)
    except Exception as e:
        flash('Error mengambil data kandidat!', 'error')
        print(f"Vote page error: {e}")
        return redirect(url_for('login'))


# ==================== ROUTES ADMIN ====================

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    try:
        # Hitung statistik
        result_kandidat = fetch_all('SELECT COUNT(*) as total FROM kandidat')
        total_kandidat = result_kandidat[0]['total'] if result_kandidat else 0
        
        result_votes = fetch_all('SELECT COUNT(*) as total FROM hasil_voting')
        total_votes = result_votes[0]['total'] if result_votes else 0
        
        result_codes = fetch_all('SELECT COUNT(*) as total FROM codes WHERE used = 0')
        available_codes = result_codes[0]['total'] if result_codes else 0
    except Exception as e:
        flash('Error mengambil data dashboard!')
        total_kandidat = total_votes = available_codes = 0
        print(f"Dashboard error: {e}")
    
    return render_template('admin_dashboard.html', 
                         total_kandidat=total_kandidat,
                         total_votes=total_votes,
                         available_codes=available_codes)

@app.route('/admin/add-kandidat', methods=['GET', 'POST'])
def add_kandidat():
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        nama = request.form.get('nama')
        
        try:
            execute_query('INSERT INTO kandidat (nama) VALUES (%s)', (nama,))
            flash('Kandidat berhasil ditambahkan!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash('Error menambah kandidat!', 'error')
            print(f"Add kandidat error: {e}")
    
    return render_template('add_kandidat.html')

@app.route('/admin/kelola-kandidat')
def kelola_kandidat():
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    try:
        kandidat_list = fetch_all('SELECT * FROM kandidat ORDER BY id')
    except Exception as e:
        flash('Error mengambil data kandidat!')
        kandidat_list = []
        print(f"Kelola kandidat error: {e}")
    
    return render_template('kelola_kandidat.html', kandidat_list=kandidat_list)

@app.route('/admin/hapus-kandidat/<int:id>')
def hapus_kandidat(id):
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    try:
        execute_query('DELETE FROM kandidat WHERE id = %s', (id,))
        flash('Kandidat berhasil dihapus!', 'success')
    except Exception as e:
        flash('Error menghapus kandidat!', 'error')
        print(f"Hapus kandidat error: {e}")
    
    return redirect(url_for('kelola_kandidat'))

# ==================== ROUTES UTAMA ====================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_type = request.form.get('login_type')
        
        if login_type == 'admin':
            username = request.form.get('username')
            password = request.form.get('password')

            password_md5 = hashlib.md5(password.encode()).hexdigest()
            
            try:
                result = fetch_all(
                    'SELECT * FROM admin WHERE username = %s AND password = %s',
                    (username, password_md5)
                )
                
                if result:
                    admin = result[0]
                    session['admin'] = username
                    session['admin_id'] = admin['id']
                    flash(f'Selamat datang, {username}!', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('login') + '?login_error=admin')
            except Exception as e:
                print(f"Admin login error: {e}")
                return redirect(url_for('login') + '?login_error=admin')
                
        elif login_type == 'siswa':
            flash('Silakan gunakan form WhatsApp untuk request kode', 'info')
    
    return render_template('login.html')


@app.route('/request-code', methods=['POST'])
def request_code():
    """Handle request kode voting via WhatsApp"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'message': 'Data tidak valid'}), 400
    
    no_wa = data.get('no_wa', '').strip()
    
    if not no_wa:
        return jsonify({'success': False, 'message': 'Nomor WA kosong'}), 400
    
    if not no_wa.isdigit() or len(no_wa) < 10:
        return jsonify({'success': False, 'message': 'Format nomor WhatsApp tidak valid'}), 400
    
    try:
        result = fetch_all(
            "SELECT * FROM siswa_request WHERE no_wa = %s AND waktu_request > DATE_SUB(NOW(), INTERVAL 1 DAY)",
            (no_wa,)
        )
        
        if result:
            return jsonify({
                'success': False, 
                'message': 'Anda hanya bisa meminta kode 1x dalam 24 jam.'
            }), 400
        
        kode = str(random.randint(100000, 999999))
        
        db_success = execute_query(
            """INSERT INTO siswa_request (no_wa, kode, waktu_request, sudah_vote) 
               VALUES (%s, %s, NOW(), 0)""",
            (no_wa, kode)
        )
        
        if not db_success:
            return jsonify({
                'success': False, 
                'message': 'Gagal menyimpan ke database.'
            }), 500

        
        # Kirim pesan WhatsApp
        pesan = f"""Halo, ini kode voting kamu:

*KODE: {kode}*

Gunakan kode ini untuk login dan melakukan voting. Kode hanya berlaku sekali."""
        
        # Konfigurasi WhatsApp
        FONNTE_API_KEY = "kR4MEbxk5Z2Pnwt8iXS6"
        headers = {"Authorization": FONNTE_API_KEY}
        
        # Format nomor
        if no_wa.startswith('0'):
            phone_to_send = '62' + no_wa[1:]
        else:
            phone_to_send = no_wa
        
        try:
            wa_response = requests.post(
                "https://api.fonnte.com/send",
                headers=headers,
                data={
                    'target': phone_to_send,
                    'message': pesan,
                    'countryCode': '62'
                },
                timeout=30
            )
            
            if wa_response.status_code == 200:
                # SIMPAN SESSION
                session.permanent = True
                session['pending_wa'] = no_wa
                session['pending_kode'] = kode
                
                return jsonify({
                    'success': True, 
                    'message': 'Kode telah dikirim ke WhatsApp.'
                })
            else:
                session['pending_wa'] = no_wa
                session['pending_kode'] = kode
                return jsonify({
                    'success': True, 
                    'message': 'Kode telah dibuat. Silakan cek WhatsApp Anda.'
                })
                
        except Exception as wa_error:
            session['pending_wa'] = no_wa
            session['pending_kode'] = kode
            return jsonify({
                'success': True, 
                'message': 'Kode telah dibuat. Silakan cek WhatsApp Anda.'
            })
            
    except Exception as e:
        print(f"Error in request_code: {e}")
        return jsonify({
            'success': False, 
            'message': 'Terjadi kesalahan server. Silakan coba lagi.'
        }), 500

@app.route('/verify-code', methods=['GET', 'POST'])
def verify_code():
    """Verifikasi kode voting"""
    
    if request.method == 'POST':
        kode_input = request.form.get('kode', '').strip()
        no_wa = session.get('pending_wa')
        stored_kode = session.get('pending_kode')
        
        if not no_wa or not kode_input:
            flash('Data tidak lengkap! Silakan request kode lagi.')
            return redirect(url_for('login'))
        
        try:
            # CEK 1: Verifikasi dengan kode di session
            if stored_kode and kode_input == stored_kode:
                # Update database
                db_success = execute_query(
                    'UPDATE siswa_request SET sudah_vote = 1 WHERE no_wa = %s AND kode = %s',
                    (no_wa, kode_input)
                )
                
                if db_success:
                    session['voter_allowed'] = True
                    session.pop('pending_wa', None)
                    session.pop('pending_kode', None)
                    return redirect(url_for('vote'))
                else:
                    flash('Error update database!')
            
            # CEK 2: Verifikasi dengan database
            else:
                result = fetch_all(
                    'SELECT * FROM siswa_request WHERE no_wa = %s AND kode = %s AND sudah_vote = 0',
                    (no_wa, kode_input)
                )
                
                if result:
                    # Update database
                    db_success = execute_query(
                        'UPDATE siswa_request SET sudah_vote = 1 WHERE no_wa = %s AND kode = %s',
                        (no_wa, kode_input)
                    )
                    
                    if db_success:
                        session['voter_allowed'] = True
                        session.pop('pending_wa', None)
                        session.pop('pending_kode', None)
                        return redirect(url_for('vote'))
                    else:
                        flash('Error update database!')
                else:
                    flash('Kode salah atau sudah digunakan!')
                    
        except Exception as e:
            flash('Error saat verifikasi kode!')
            print(f"Verify code error: {e}")
    
    return render_template('verify_code.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)