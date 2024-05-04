import time

import inquirer
from pyfiglet import figlet_format
import uuid
import threading
import yaml
import socket
from timestamp_print import timestamped_print

# fancy ascii header with figlet
print("\nNetwork Monitor ver 1.1, developed by Glen Brochard\n")
print(figlet_format("Network Monitor", font="cybermedium"))

# create some default ids for the default parameters (placeholders in case user just wants to run the program with
# something)
default_ids = []
for i in range(8):
    default_ids.append(str(uuid.uuid1().int))

# these were updated - each 'type' of service (ping, http, etc.) will contain a dictionary of unique ids (default ids)
# each tied to a specific set of parameters - yes there is a lot of nesting, but it seemed like a decent way to allow
# for individualized specifications for every service to be run
services_params = {
    "Ping": {default_ids[0]: {"host": "52.27.33.250", "ttl": 64, "timeout": 1, "sequence_number": 1, "interval": 5}},
    "Traceroute": {default_ids[1]: {"host": "52.27.33.250", "max_hops": 50, "pings_per_hop": 1,
                                    "verbose": True, "interval": 5}},
    "HTTP": {default_ids[2]: {"url": "http://gaia.cs.umass.edu", "interval": 5}},
    "HTTPS": {default_ids[3]: {"url": "https://www.google.com", "timeout": 5, "interval": 5}},
    "NTP": {default_ids[4]: {"server": "pool.ntp.org", "interval": 5}},
    "DNS": {default_ids[5]: {"server": "8.8.8.8", "query": "www.google.com", "record_type": "A", "interval": 5}},
    "TCP": {default_ids[6]: {"ip_address": "127.0.0.1", "port": 8000, "interval": 5}},
    "UDP": {default_ids[7]: {"ip_address": "127.0.0.1", "port": 6000, "timeout": 3, "interval": 5}}
}

# global list of available services to allow for activation/deactivation using inquirer prompt in configuration
services = ["Ping", "Traceroute", "HTTP", "HTTPS", "DNS", "NTP", "TCP", "UDP"]


def tcp_client_worker(stop_event: threading.Event, service_type: str, service_id: int,
                      service_params: dict):
    # Create socket:
    # as with the server script, create socket with AF_INET (IPv4) and STREAMing TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Specify server and port:
    # Define server IP (will be localhost for now) and server port
    serv_address = '127.0.0.1'
    serv_port = 5000

    client_socket.connect((serv_address, serv_port))
    try:
        # Send and Recv data:
        # sendall(): send data to the server
        msg = service_type + " " + str(service_id)
        for key in service_params.keys():
            msg += " " + str(service_params[key])

        client_socket.send(msg.encode())

        # recv(): get data from the server, specifying buffer (1024 bytes in this instance)
        while not stop_event.is_set():
            try:
                response = client_socket.recv(1024)
                if response:
                    timestamped_print(f"Received: {response.decode()}")
            finally:
                time.sleep(1)
                continue
    except Exception as e:
        print("Error", e)


def stop_thread():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Specify server and port:
        # Define server IP (will be localhost for now) and server port
        serv_address = '127.0.0.1'
        serv_port = 5000

        client_socket.connect((serv_address, serv_port))
        message = 'stop'
        message = message.encode()
        client_socket.send(message)
        client_socket.close()

    except Exception as e:
        print("Error", e)


def main(active_services, services_parameters):
    display_main = True

    try:
        while display_main:
            menu_choice = [
                inquirer.List(
                    "main_choice",
                    message="Please choose an option",
                    choices=['configure', 'start services', 'exit'],
                ),
            ]

            user_choice = inquirer.prompt(menu_choice)

            match user_choice['main_choice']:
                case "exit":
                    display_main = False

                case "configure":

                    display_config = True

                    while display_config:

                        config_choice = [
                            inquirer.List(
                                "config_choice",
                                message="Please select an option",
                                choices=["activate|deactivate services", "create new service",
                                         "remove existing service", "save config", "load config",
                                         "reset to default configuration", "return to main"],
                            ),
                        ]

                        user_choice = inquirer.prompt(config_choice)

                        match user_choice['config_choice']:
                            # prompt with checkboxes that can be selected or deselected (list will be used for 'start all'
                            # choice within 'start|stop services'
                            case "activate|deactivate services":

                                user_prompt = [
                                    inquirer.Checkbox(
                                        "services",
                                        message="Please select services which should be active (use arrow keys to set/unset)",
                                        choices=["Ping", "Traceroute", "HTTP", "HTTPS", "DNS", "NTP", "TCP", "UDP"],
                                        default=active_services,
                                    ),
                                ]

                                user_active_selection = inquirer.prompt(user_prompt)
                                # this will set the active services to only those selected and pass that back to main
                                active_services = user_active_selection['services']

                                continue

                            case "create new service":

                                service_prompt = [
                                    inquirer.List(
                                        "selected_service",
                                        message="Please select the type of monitoring service to create",
                                        choices=["Ping", "Traceroute", "HTTP", "HTTPS", "DNS", "NTP", "TCP", "UDP"],
                                    ),
                                ]

                                user_service_choice = inquirer.prompt(service_prompt)
                                service_type = user_service_choice['selected_service']

                                match service_type:

                                    # TODO CREATE FUNCTION TO COLLAPSE THESE INTO ONE, PASS LIST OF PARAMETERS
                                    case "Ping":
                                        service_parameters = [
                                            inquirer.Text("host", "Enter host"),
                                            inquirer.Text("ttl", "Enter time-to-live (default 64)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("timeout", "Enter timeout (default 1)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("sequence_number", "Enter sequence number (default 1)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric())
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['Ping'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'Ping' parameters (all):\n")
                                        for key in services_parameters['Ping'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['Ping'][key].keys():
                                                print(k + ": " + str(services_parameters['Ping'][key][k]), end="  ")
                                            print("")
                                        print("")

                                    case "Traceroute":
                                        service_parameters = [
                                            inquirer.Text("host", "Enter host"),
                                            inquirer.Text("max_hops", "Enter max-hops (default 30)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("pings_per_hop", "Enter pings-per-hop (default 1)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("verbose", "Enter True/False for verbosity (default False)"),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric())
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['Traceroute'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'Traceroute' parameters (all):\n")
                                        for key in services_parameters['Traceroute'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['Traceroute'][key].keys():
                                                print(k + ": " + str(services_parameters['Traceroute'][key][k]),
                                                      end="  ")
                                            print("")
                                        print("")

                                    case "HTTP":
                                        service_parameters = [
                                            inquirer.Text("url", "Enter URL"),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['HTTP'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'HTTP' parameters (all):\n")
                                        for key in services_parameters['HTTP'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['HTTP'][key].keys():
                                                print(k + ": " + str(services_parameters['HTTP'][key][k]), end="  ")
                                            print("")
                                        print("")

                                    case "HTTPS":
                                        service_parameters = [
                                            inquirer.Text("url", "Enter URL"),
                                            inquirer.Text("timeout", "Enter timeout (default 1)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['HTTP'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'HTTPS' parameters (all):\n")
                                        for key in services_parameters['HTTPS'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['HTTPS'][key].keys():
                                                print(k + ": " + str(services_parameters['HTTPS'][key][k]), end="  ")
                                            print("")
                                        print("")

                                    case "NTP":
                                        service_parameters = [
                                            inquirer.Text("server", "Enter server"),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['NTP'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'NTP' parameters (all):\n")
                                        for key in services_parameters['NTP'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['NTP'][key].keys():
                                                print(k + ": " + str(services_parameters['NTP'][key][k]), end="  ")
                                            print("")
                                        print("")

                                    case "DNS":
                                        service_parameters = [
                                            inquirer.Text("server", "Enter server"),
                                            inquirer.Text("query", "Enter domain name to query"),
                                            inquirer.Text("record_type", "Enter record_type (A, AAAA, CNAME, etc)"),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['DNS'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'DNS' parameters (all):\n")
                                        for key in services_parameters['DNS'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['DNS'][key].keys():
                                                print(k + ": " + str(services_parameters['DNS'][key][k]), end="  ")
                                            print("")
                                        print("")

                                    case "TCP":
                                        service_parameters = [
                                            inquirer.Text("ip_address", "Enter IP"),
                                            inquirer.Text("port", "Enter port", validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['TCP'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'TCP' parameters (all):\n")
                                        for key in services_parameters['TCP'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['TCP'][key].keys():
                                                print(k + ": " + str(services_parameters['TCP'][key][k]), end="  ")
                                            print("")
                                        print("")

                                    case "UDP":
                                        service_parameters = [
                                            inquirer.Text("ip_address", "Enter IP"),
                                            inquirer.Text("port", "Enter port", validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("timeout", "Enter timeout (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                            inquirer.Text("interval", "Enter monitoring interval (seconds)",
                                                          validate=lambda _, c: c.isnumeric()),
                                        ]

                                        parameters = inquirer.prompt(service_parameters)
                                        services_parameters['UDP'][str(uuid.uuid1().int)] = parameters

                                        # notify user what has been added and all  of the current services (with associated IDs)
                                        # exist for a specific type of service
                                        print(f"\nService created, current 'UDP' parameters (all):\n")
                                        for key in services_parameters['UDP'].keys():
                                            print("serviceID: " + key, end="  ")
                                            for k in services_parameters['UDP'][key].keys():
                                                print(k + ": " + str(services_parameters['UDP'][key][k]), end="  ")
                                            print("")
                                        print("")

                                continue

                            case "remove existing service":
                                # show existing services for every type
                                for key in services_parameters.keys():
                                    print(key)
                                    for _ in range(len(key)):
                                        print("-", end="")
                                    print("", flush=True)
                                    for service_id in services_parameters[key].keys():
                                        print("serviceID: " + str(service_id), end=" ")
                                        for param in services_parameters[key][service_id].keys():
                                            print(param + ": " + str(services_parameters[key][service_id][param]),
                                                  end="  ")
                                        print("")
                                    print("", flush=True)

                                prompt = [
                                    inquirer.List(
                                        "service_type",
                                        message="Please select the service type being removed",
                                        choices=["Ping", "Traceroute", "HTTP", "HTTPS", "DNS", "NTP", "TCP", "UDP"],
                                    )
                                ]

                                service_choice = inquirer.prompt(prompt)
                                service_choice = service_choice['service_type']

                                user_choice = input("Please enter the serviceID which you would like to remove "
                                                    "(copy/paste for accuracy): ")

                                try:
                                    del services_parameters[service_choice][user_choice]
                                except KeyError:
                                    print("\nInvalid key.\n")
                                    continue

                                print("\nService removed.\n")
                                continue

                            case "save config":
                                save_prompt = [
                                    inquirer.List(
                                        "save_choice",
                                        message="Save config to file? (No to exit to config main)",
                                        choices=["Yes", "No"],
                                    )
                                ]

                                user_input = inquirer.prompt(save_prompt)

                                if user_input['save_choice'] == "No":
                                    continue
                                elif user_input['save_choice'] == "Yes":
                                    with open("./config/params_config.yaml", mode="wt") as f:
                                        yaml.safe_dump(services_params, f)
                                        f.close()
                                    with open("./config/active_services_config.yaml", mode="wt") as f:
                                        yaml.safe_dump(active_services, f)
                                        f.close()

                                    print("Parameters and active services saved in ./config/ "
                                          "(param_config.yaml, active_services_config.yaml), returning to main"
                                          "config menu.\n")

                            case "load config":
                                load_prompt = [
                                    inquirer.List(
                                        "load_choice",
                                        message="Load config from file? (No to exit to config main), files to be"
                                                "loaded are active_services_config.yaml & params_config.yaml",
                                        choices=["Yes", "No"],
                                    )
                                ]

                                user_input = inquirer.prompt(load_prompt)

                                if user_input['load_choice'] == "No":
                                    continue
                                elif user_input['load_choice'] == "Yes":
                                    with open("./config/params_config.yaml", mode="r") as f:
                                        services_parameters = yaml.safe_load(f)
                                        f.close()
                                    with open("./config/active_services_config.yaml", mode="r") as f:
                                        active_services = yaml.safe_load(f)
                                        f.close()

                                    print("Parameters and active services loaded from ./config/ "
                                          "(param_config.yaml, active_services_config.yaml), returning to main"
                                          "config menu.\n")

                            case "reset to default configuration":
                                reset_prompt = [
                                    inquirer.List(
                                        "reset_choice",
                                        message="Reset config? (No to exit to config main), files to be"
                                                "loaded are def_active_services_config.yaml & def_params_config.yaml.",
                                        choices=["Yes", "No"],
                                    )
                                ]

                                user_input = inquirer.prompt(reset_prompt)
                                if user_input['reset_choice'] == "No":
                                    continue
                                elif user_input['reset_choice'] == "Yes":
                                    with open("./config/def_params_config.yaml", mode="r") as f:
                                        services_parameters = yaml.safe_load(f)
                                        f.close()
                                    with open("./config/def_active_services_config.yaml", mode="r") as f:
                                        active_services = yaml.safe_load(f)
                                        f.close()

                                    print("Parameters and active services loaded from ./config/ "
                                          "(def_param_config.yaml, def_active_services_config.yaml), returning to main"
                                          "config menu.\n")

                            case "return to main":
                                display_config = False

                # TODO FLESH THIS OUT
                case "start services":
                    print("Ctrl + c to end monitoring at any time.")
                    print(active_services)
                    # event to signal worker to stop
                    stop_event: threading.Event = threading.Event()

                    # iterate params dict and send each as an individual message to the monitoring server
                    for service_type in services_parameters.keys():
                        if service_type in active_services:
                            for service_id in services_parameters[service_type].keys():
                                w = threading.Thread(target=tcp_client_worker, args=(stop_event,),
                                                     kwargs={'service_type': service_type,
                                                             'service_id': service_id,
                                                             'service_params': services_parameters[service_type][
                                                                 service_id]}
                                                     )
                                w.start()
                    print("")

                    try:
                        while True:
                            time.sleep(.1)

                    except KeyboardInterrupt:
                        print("\nAttempting to close monitoring threads...\n", flush=True)
                        stop_remote = threading.Thread(target=stop_thread)
                        stop_remote.start()

                        stop_event.set()

                    finally:
                        time.sleep(1)
                        continue

    finally:
        return


if __name__ == "__main__":
    main(services, services_params)
