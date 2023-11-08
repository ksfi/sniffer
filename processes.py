import scapy.all as sc

from typing import Optional, List, Any, Tuple, Dict

def network_interfaces() -> List[str]:
  '''
  returns List[str]: list of interfaces
  '''
  return sc.get_if_list()

def display(connected_processes: List[Tuple[str, str, List[Any]]]) -> None:
  for conn in connected_processes:
    print(f"Process Name: {conn[0]}, PID: {[conn[1]]}")
    print(f"Status {conn[2]}")
    for c in conn[3]:
      try:
        print(f"  -> IP: {c.laddr.ip}, Port: {c.laddr.port}")
      except: pass
    print("---------------------------")

class _Processes:
  @staticmethod
  def watch(_kind:str='tcp', _display:bool=False) -> List[Tuple[str, str, List[Any]]]:
    '''
    returns a List[Tuple[str, str, List[Any]]] [(process_name: str, process_id: str, connections: List[pconn]),...]
    corresponding to current processes with a tcp (by default, can be modified) connection ongoing.
    '''
    ret: List[Tuple[str, str, List[Any]]] = []
    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_info = process.info
            process_name = process_info['name']
            process_pid = process_info['pid']
            if process_name:
                connections = psutil.Process(process_pid).connections(kind=_kind)
                if len(connections) > 0:
                  ret.append((process_name, process_pid, connections[0].status, connections))
        except: pass
    if _display:
       display(ret)
    return ret

Processes = _Processes

if __name__ == "__main__":
  print(network_interfaces())