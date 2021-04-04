from classes import Call, Client


def calculate_call_count(messages):
    return len("".join(messages))


def generate_call(
    packet_start_time, call_id, branch, user_agent, sourcesync, clients, character
):
    call = Call(
        packet_start_time=packet_start_time,
        call_id=call_id,
        branch=branch,
        sourcesync=sourcesync,
        caller=clients[0],
        receiver=clients[1],
        user_agent=user_agent,
        character=character,
    )
    call.create_packets()
    return call


def generate_clients(clients):
    clients_list = []
    for client in clients:
        clients_list.append(
            Client(
                name=client["name"],
                username=client["username"],
                ip=client["ip"],
            )
        )
    return clients_list
