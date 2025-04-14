import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

connected_users = {}  # user_id → socket_id

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

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
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
    cursor.execute("SELECT * FROM product")
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
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
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


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

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
    cursor.execute("SELECT * FROM product WHERE title LIKE ?", ('%' + query + '%',))
    results = cursor.fetchall()

    # 사용자 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('search_results.html', products=results, user=current_user, query=query)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if not current_user or current_user['is_admin'] != 1:
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))

    # 모든 유저, 상품, 신고 불러오기
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    cursor.execute("SELECT * FROM report")
    reports = cursor.fetchall()

    return render_template('admin_dashboard.html', users=users, products=products, reports=reports, user=current_user)

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

    receiver_id = request.form['receiver_id']
    content = request.form['content']
    sender_id = session['user_id']
    msg_id = str(uuid.uuid4())

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO message (id, sender_id, receiver_id, content)
        VALUES (?, ?, ?, ?)
    """, (msg_id, sender_id, receiver_id, content))
    db.commit()
    flash('메시지가 전송되었습니다.')
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
