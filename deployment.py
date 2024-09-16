import os
import subprocess
import sys


def create_virtual_env():
    """
    Создание виртуального окружения, если оно не существует.
    """
    print("Создается виртуальное окружение...")
    subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)


def install_requirements():
    """
    Установка зависимостей из requirements.txt
    """
    print("Устанавливаются зависимости...")
    pip_executable = os.path.join('venv', 'Scripts', 'pip') if os.name == 'nt' else os.path.join('venv', 'bin', 'pip')
    subprocess.run([pip_executable, 'install', '-r', 'requirements.txt'], check=True)


def run_application():
    """
    Запуск приложения.
    """
    print("Запускается приложение...")
    python_executable = os.path.join('venv', 'Scripts', 'python') if os.name == 'nt' else os.path.join('venv', 'bin',
                                                                                                       'python')
    subprocess.run([python_executable, 'app.py'], check=True)


def main():
    """
    Основная функция, которая создаёт виртуальное окружение,
    устанавливает зависимости и запускает приложение.
    """
    try:
        # Проверка на существование виртуального окружения
        if not os.path.exists('venv'):
            create_virtual_env()
            install_requirements()

        # Запуск приложения
        run_application()

    except subprocess.CalledProcessError as e:
        print(f"Произошла ошибка: {e}")
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}")


if __name__ == '__main__':
    main()