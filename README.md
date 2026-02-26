# sky
空暂停web
使用方法：

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ADMIN_USER=admin
export ADMIN_PASSWORD='换成强密码'
export FLASK_SECRET='换成随机长字符串'
python app.py


浏览器访问：http://127.0.0.1:9876（BasicAuth 登录）。
