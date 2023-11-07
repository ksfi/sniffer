import psutil
import socket

class Processes:
  @staticmethod
  def watch(_kind:str='tcp'):
    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_info = process.info
            process_name = process_info['name']
            process_pid = process_info['pid']
            if process_name:
                connections = psutil.Process(process_pid).connections(kind=_kind)
                if len(connections) > 0:
                  print(f"Process Name: {process_name}, PID: {process_pid}")
                  print(f"Status {connections[0].status}")
                  for conn in connections:
                      if conn.laddr.ip and conn.laddr.port:
                          print(f"  -> IP: {conn.laddr.ip}, Port: {conn.laddr.port}")
        except:
            pass

if __name__ == "__main__":
   Processes.watch()