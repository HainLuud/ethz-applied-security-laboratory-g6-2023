#!/usr/bin/env python3

from app import app, db


def main():
    with app.app_context(), db.engine.connect() as conn:
        while True:
            user_input = input('sql> ')
            if user_input.lower() == 'exit':
                break
            try:
                result = conn.execute(db.text(user_input))
                if result.returns_rows:
                    for row in result:
                        print(row)
            except Exception as e:
                print(e)


if __name__ == '__main__':
    main()
