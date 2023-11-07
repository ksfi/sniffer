import psutil
import socket

class Processes:
  @staticmethod
  def watch():
    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_info = process.info
            process_name = process_info['name']
            process_pid = process_info['pid']
            if process_name:
                connections = psutil.Process(process_pid).connections()
                if connections:
                  print(f"Process Name: {process_name}, PID: {process_pid}")
                for conn in connections:
                    if conn.laddr.ip and conn.laddr.port:
                        print(f"  -> IP: {conn.laddr.ip}, Port: {conn.laddr.port}")
        except:
            pass
