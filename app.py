import sqlite3
import uuid
import re
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, Response
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

connected_users = {}  # user_id → socket_id

import re

FORBIDDEN_USERNAMES = {"admin", "root", "system", "administrator"}

def is_valid_username(username):
    if not username:
        return False, "사용자명을 입력해주세요."
    if len(username) < 4 or len(username) > 20:
        return False, "사용자명은 4자 이상 20자 이하로 입력해야 합니다."
    if not re.fullmatch(r'^[a-zA-Z0-9_]+$', username):
        return False, "사용자명은 영문자, 숫자, 언더스코어(_)만 사용할 수 있습니다."
    if username.lower() in FORBIDDEN_USERNAMES:
        return False, "해당 사용자명은 사용할 수 없습니다."
    if username.isdigit():
        return False, "숫자로만 이루어진 사용자명은 사용할 수 없습니다."
    return True, ""

def is_valid_password(password):
    if not password:
        return False, "비밀번호를 입력해주세요."
    if len(password) < 8 or len(password) > 30:
        return False, "비밀번호는 8자 이상 30자 이하로 입력해야 합니다."
    if not re.fullmatch(r'^[a-zA-Z0-9!@#$%^&*()_+=\-]+$', password):
        return False, "비밀번호에 허용되지 않은 문자가 포함되어 있습니다."
    
    # 보안 강화: 대문자, 소문자, 숫자, 특수문자 최소 1개 이상
    if not re.search(r'[A-Z]', password):
        return False, "비밀번호에는 대문자가 최소 1개 포함되어야 합니다."
    if not re.search(r'[a-z]', password):
        return False, "비밀번호에는 소문자가 최소 1개 포함되어야 합니다."
    if not re.search(r'[0-9]', password):
        return False, "비밀번호에는 숫자가 최소 1개 포함되어야 합니다."
    if not re.search(r'[!@#$%^&*()_+=\-]', password):
        return False, "비밀번호에는 특수문자가 최소 1개 포함되어야 합니다."
    
    return True, ""


@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        connected_users[session['user_id']] = request.sid

@socketio.on('private_message')
def handle_private_message(data):
    sender_id = session.get('user_id')
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    if not sender_id or not receiver_id or not message:
        return
    
    receiver_sid = connected_users.get(receiver_id)
    if receiver_sid:
        socketio.emit('private_message', {
            'from': sender_id,
            'message': message
        }, to=receiver_sid)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        connected_users.pop(session['user_id'], None)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블 수정됨
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                status TEXT DEFAULT 'active',
                balance INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                report_count INTEGER DEFAULT 0,   
                is_locked INTEGER DEFAULT 0       
            )
        """)

        # 상품 테이블 생성 - report_count 컬럼 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'visible',
                report_count INTEGER DEFAULT 0
            )
        """)

        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT,
                reason TEXT NOT NULL,
                product_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 사용자와 상품 간의 관계 테이블 생성 (예: 구매 기록)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS purchase (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user(id),
                FOREIGN KEY(product_id) REFERENCES product(id)
            )
        """)

        # **이체 테이블 추가**
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                transfer_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES user(id),
                FOREIGN KEY(receiver_id) REFERENCES user(id)
            )
        """)

        # 나머지 테이블 수정 코드...

        # 테이블 수정: 열이 존재하지 않는 경우 추가
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN status TEXT DEFAULT 'active'")
        except sqlite3.OperationalError:
            pass  # 이미 있으면 무시

        try:
            cursor.execute("ALTER TABLE product ADD COLUMN status TEXT DEFAULT 'visible'")
        except sqlite3.OperationalError:
            pass  # 이미 있으면 무시

        try:
            cursor.execute("ALTER TABLE product ADD COLUMN report_count INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # 이미 있으면 무시

        try:
            cursor.execute("ALTER TABLE report ADD COLUMN product_id TEXT")
        except sqlite3.OperationalError:
            pass  # 이미 있으면 무시

        db.commit()


# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
from flask import request, redirect, url_for, flash, render_template, Response
from werkzeug.security import generate_password_hash
import uuid, json, sqlite3
import logging

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            valid_user, msg_user = is_valid_username(username)
            valid_pass, msg_pass = is_valid_password(password)

            # 클라이언트가 JSON(AJAX) 요청한 경우
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                if not valid_user:
                    return Response(
                        json.dumps({"error": msg_user}, ensure_ascii=False),
                        content_type="application/json; charset=utf-8",
                        status=400
                    )
                if not valid_pass:
                    return Response(
                        json.dumps({"error": msg_pass}, ensure_ascii=False),
                        content_type="application/json; charset=utf-8",
                        status=400
                    )

                # DB 연결 및 중복 확인
                db = get_db()
                cursor = db.cursor()
                cursor.execute("SELECT 1 FROM user WHERE username = ?", (username,))
                if cursor.fetchone():
                    return Response(
                        json.dumps({"error": "이미 존재하는 사용자명입니다."}, ensure_ascii=False),
                        content_type="application/json; charset=utf-8",
                        status=400
                    )

                # 비밀번호 해시 및 사용자 생성
                hashed_password = generate_password_hash(password)
                user_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                    (user_id, username, hashed_password)
                )
                db.commit()

                return Response(
                    json.dumps({"message": "회원가입이 완료되었습니다."}, ensure_ascii=False),
                    content_type="application/json; charset=utf-8",
                    status=200
                )

            # 일반 폼 제출 처리
            if not valid_user:
                flash(msg_user)
                return redirect(url_for('register'))
            if not valid_pass:
                flash(msg_pass)
                return redirect(url_for('register'))

            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM user WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("이미 존재하는 사용자명입니다.")
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)
            user_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                (user_id, username, hashed_password)
            )
            db.commit()

            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            return redirect(url_for('login'))

        except sqlite3.Error as e:
            logging.exception("DB 오류 발생: %s", e)
            return Response(
                json.dumps({"error": "서버 오류가 발생했습니다."}, ensure_ascii=False),
                content_type="application/json; charset=utf-8",
                status=500
            )

        except Exception as e:
            logging.exception("예외 발생: %s", e)
            return Response(
                json.dumps({"error": "알 수 없는 오류가 발생했습니다."}, ensure_ascii=False),
                content_type="application/json; charset=utf-8",
                status=500
            )

    return render_template('register.html')

from flask import request, redirect, url_for, flash, render_template, session, Response
from werkzeug.security import check_password_hash
import sqlite3
import logging

# 로그인 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            # DB 연결 및 사용자 확인
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            user = cursor.fetchone()

            # 사용자명 또는 비밀번호가 틀린 경우
            if not user or not check_password_hash(user['password'], password):
                logging.warning(f"Failed login attempt for username: {username}")
                flash('사용자명 또는 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('login'))

            # 잠긴 계정 확인
            if user['is_locked']:
                flash('이 계정은 신고 누적으로 잠겼습니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))

            # 계정 상태 확인 (정지, 휴면)
            user_status = user['status']
            if user_status == 'suspended':
                flash('이 계정은 현재 사용이 정지되었습니다.')
                return redirect(url_for('login'))
            elif user_status == 'inactive':
                flash('이 계정은 휴면 상태입니다. 관리자에게 문의하십시오.')
                return redirect(url_for('login'))

            # 로그인 성공 시 세션 설정
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True  # 세션 지속 시간 설정

            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        except sqlite3.Error as e:
            logging.exception("DB 오류 발생: %s", e)
            return Response(
                json.dumps({"error": "서버 오류가 발생했습니다."}, ensure_ascii=False),
                content_type="application/json; charset=utf-8",
                status=500
            )
        except Exception as e:
            logging.exception("예외 발생: %s", e)
            return Response(
                json.dumps({"error": "알 수 없는 오류가 발생했습니다."}, ensure_ascii=False),
                content_type="application/json; charset=utf-8",
                status=500
            )

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product WHERE status != 'hidden'")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ? AND status != 'hidden'", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    # 현재 로그인한 사용자 정보도 같이 넘기기
    current_user = None
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()

    return render_template('view_product.html', product=product, seller=seller, user=current_user)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_id = request.form['target_id']
        product_id = request.form.get('product_id', '')  # 빈 문자열이 기본값
        reason = request.form['reason']
        reporter_id = session['user_id']  # 신고하는 사람의 ID

        # 자기 자신을 신고하는지 확인
        if target_id != 'none' and target_id == reporter_id:
            flash("자기 자신을 신고할 수 없습니다.")
            return redirect(url_for('report'))

        # 신고 정보 저장
        report_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, product_id, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (report_id, reporter_id, target_id if target_id != 'none' else None, product_id if product_id else None, reason))
        
        # 사용자 신고 처리
        if target_id != 'none':
            # 신고당한 사용자의 report_count 증가
            cursor.execute("UPDATE user SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            
            # 신고 횟수 확인
            cursor.execute("SELECT report_count FROM user WHERE id = ?", (target_id,))
            user = cursor.fetchone()
            
            # 신고가 3회 이상이면 계정 상태를 inactive로 변경
            if user and user['report_count'] >= 3:
                cursor.execute("UPDATE user SET status = 'inactive' WHERE id = ?", (target_id,))
                flash("해당 사용자는 신고 누적으로 휴면 계정 처리되었습니다.")

        # 상품 신고 처리
        if product_id:
            # 신고된 상품의 report_count 증가
            cursor.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (product_id,))
            
            # 상품 신고 횟수 확인
            cursor.execute("SELECT report_count FROM product WHERE id = ?", (product_id,))
            product = cursor.fetchone()
            
            # 상품 신고가 3회 이상이면 상태를 hidden으로 변경
            if product and product['report_count'] >= 3:
                cursor.execute("UPDATE product SET status = 'hidden' WHERE id = ?", (product_id,))
                flash("해당 상품은 신고 누적으로 비공개 처리되었습니다.")

        db.commit()
        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    # GET 요청: 사용자와 상품 리스트 가져오기
    cursor.execute("SELECT id, username FROM user WHERE id != ?", (session['user_id'],))
    users = cursor.fetchall()

    cursor.execute("SELECT id, title FROM product WHERE status != 'hidden'")
    products = cursor.fetchall()

    return render_template('report.html', users=users, products=products)

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 상품 검색 기능
@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '').strip()
    db = get_db()
    cursor = db.cursor()

    # 제목에 검색어가 포함된 상품 검색
    cursor.execute("SELECT * FROM product WHERE title LIKE ? AND status != 'hidden'", ('%' + query + '%',))
    results = cursor.fetchall()

    # 사용자 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('search_results.html', products=results, user=current_user, query=query)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if not current_user or not current_user['is_admin']:
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    # 전체 사용자 및 상품 목록 조회
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    return render_template('admin_dashboard.html', users=users, products=products, admin=current_user)

@app.route('/admin/update_user_status', methods=['POST'])
def update_user_status():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 관리자 권한 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for('dashboard'))
    
    user_id = request.form['user_id']
    new_status = request.form['status']
    reset_reports = request.form.get('reset_reports', False)
    
    # 사용자 상태 업데이트
    cursor.execute("UPDATE user SET status = ? WHERE id = ?", (new_status, user_id))
    
    # 신고 횟수 초기화 옵션
    if reset_reports:
        cursor.execute("UPDATE user SET report_count = 0 WHERE id = ?", (user_id,))
    
    db.commit()
    flash("사용자 상태가 업데이트되었습니다.")
    return redirect(url_for('admin_dashboard'))

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    current_user_id = session['user_id']

    if request.method == 'POST':
        receiver_username = request.form['receiver']
        amount = int(request.form['amount'])

        # 수신자 ID 조회
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('받는 사용자를 찾을 수 없습니다.')
            return redirect(url_for('transfer'))

        receiver_id = receiver['id']

        # 송금 트랜잭션 저장
        transfer_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO transfer (id, sender_id, receiver_id, amount)
            VALUES (?, ?, ?, ?)
        """, (transfer_id, current_user_id, receiver_id, amount))
        db.commit()

        flash(f'{receiver_username}님에게 {amount} 가상머니를 송금했습니다.')
        return redirect(url_for('dashboard'))

    # 유저 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (current_user_id,))
    current_user = cursor.fetchone()

    return render_template('transfer.html', user=current_user)

# 사용자 삭제
@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 관리자 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for('dashboard'))

    user_id = request.form['user_id']
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자가 삭제되었습니다.")
    return redirect(url_for('admin_dashboard'))

# 상품 삭제
@app.route('/admin/delete_product', methods=['POST'])
def delete_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for('dashboard'))

    product_id = request.form['product_id']
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('admin_dashboard'))

# 신고 처리
@app.route('/admin/resolve_report', methods=['POST'])
def resolve_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for('dashboard'))

    report_id = request.form['report_id']
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash("신고가 처리되었습니다.")
    return redirect(url_for('admin_dashboard'))

@app.route('/messages/<user_id>')
def view_conversation(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = session['user_id']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT * FROM message
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp
    """, (current_user, user_id, user_id, current_user))
    messages = cursor.fetchall()

    # 상대방 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    other_user = cursor.fetchone()

    return render_template('conversation.html', messages=messages, other_user=other_user)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender_id = session['user_id']
    receiver_id = request.form['receiver_id']
    content = request.form['content']
    message_id = str(uuid.uuid4())

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO message (id, sender_id, receiver_id, content)
        VALUES (?, ?, ?, ?)
    """, (message_id, sender_id, receiver_id, content))
    db.commit()

    return redirect(url_for('view_conversation', user_id=receiver_id))


@app.route('/inbox')
def inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 나에게 메시지를 보낸 사람 목록 (중복 제거)
    cursor.execute("""
        SELECT u.id, u.username
        FROM user u
        WHERE u.id IN (
            SELECT sender_id FROM message WHERE receiver_id = ?
        )
        ORDER BY u.username
    """, (session['user_id'],))
    senders = cursor.fetchall()

    return render_template('inbox.html', senders=senders)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)