import curses
import random
from curses import textpad
import time
from client import receive_udp_multicast, create_tcp_client
import json

def create_food(snake, displayBox):
    food = None
    while food is None:
        food = [random.randint(displayBox[0][0]+1, displayBox[1][0]-1), random.randint(displayBox[0][1]+1, displayBox[1][1]-1)]
        if snake in food:
            food = None
    return food

def print_score(stdsrc, screenWidth, score):
    score_msg = f'| SCORE: {score} |'
    stdsrc.addstr(1, screenWidth // 2 - len(score_msg) // 2, score_msg)
    # stdsrc.refresh()

def print_level(stdscr, screenWidth, level):
    level_message = f'| LEVEL: {level} |'
    stdscr.addstr(2, screenWidth // 2 - len(level_message) // 2, level_message)
    

def play(stdscr):
    curses.curs_set(0)
    stdscr.clear() 
    stdscr.addstr("Hello in Snake game, please click something to start the game")
    stdscr.refresh()
    stdscr.getch() 
    stdscr.clear() 
    # like sleep in while 1:
    timeout = 200
    stdscr.timeout(timeout)
    screenHeight, screenWidth = stdscr.getmaxyx()

    # corner values
    displayBox = [[3, 3], [screenHeight - 3, screenWidth -3]]

    textpad.rectangle(stdscr, displayBox[0][0], displayBox[0][1], displayBox[1][0], displayBox[1][1])

    #  the head is the first value
    snake = [[ screenHeight // 2, screenWidth // 2 + 1 ], [screenHeight // 2, screenWidth // 2], [screenHeight // 2, screenWidth // 2 - 1 ]]
    
    score = 0
    print_score(stdscr, screenWidth, score)
    
    level = 1
    print_level(stdscr, screenWidth, level)
    
    # direction where snake needs to go - default is right
    direction = curses.KEY_RIGHT


    for y, x in snake:
        stdscr.addstr(y, x, "#")
        # stdscr.refresh()

    food = [create_food(snake, displayBox)]
    food.append(create_food(snake, displayBox))
    for y, x in food:
        stdscr.addstr(y, x, "*")

    while True:
        if score % (4 * level) == 0 and score != 0:
            timeout = max(50, timeout - 40)
            level += 1
            print_level(stdscr, screenWidth, level)
            stdscr.timeout(timeout)
    
        previous_direction = direction
        # we are blocking the key for only 150 by default - then runs the loop what keeps snake moving
        key = stdscr.getch()


        # prohibit player to move opposite direction during game
        if key in [curses.KEY_RIGHT, curses.KEY_LEFT, curses.KEY_UP, curses.KEY_DOWN]:
            if (key == curses.KEY_RIGHT and previous_direction != curses.KEY_LEFT) or \
                (key == curses.KEY_LEFT and previous_direction != curses.KEY_RIGHT) or \
                (key == curses.KEY_UP and previous_direction != curses.KEY_DOWN) or \
                (key == curses.KEY_DOWN and previous_direction != curses.KEY_UP):
                    direction = key

        head = snake[0]
        
        match direction:
            case curses.KEY_RIGHT:
                new_head = [head[0], head[1] + 1]
            case curses.KEY_LEFT:
                new_head = [head[0], head[1] - 1]
            case curses.KEY_UP:
                new_head = [head[0] - 1, head[1]]
            case curses.KEY_DOWN:
                new_head = [head[0] + 1, head[1]]


        snake.insert(0, new_head)   
        
        stdscr.addstr(new_head[0], new_head[1], '#')

        if snake[0] in food:
            food.remove(snake[0])
            new_food = create_food(snake, displayBox)
            stdscr.addstr(new_food[0], new_food[1], "*")
            food.append(new_food)
            score += 1
            print_score(stdscr, screenWidth, score)
        else: 
            stdscr.addstr(snake[-1][0], snake[-1][1],  ' ')
            snake.pop()

        if snake[0][0] in [displayBox[0][0], displayBox[1][0]] or snake[0][1] in [displayBox[0][1],displayBox[1][1]] or snake[0] in snake[1:]:
            msg = "GAME OVER !"
            stdscr.addstr(screenHeight // 2, screenWidth // 2 - len(msg) // 2, msg)
            stdscr.nodelay(0)
            stdscr.getch()
            break
    return score, level


def start_game(stdscr):
    curses.curs_set(1)
    stdscr.clear()
    stdscr.addstr("Connecting to Game server\n")
    stdscr.refresh()

    server_info = receive_udp_multicast()
   
    stdscr.addstr(f"Received server info: {server_info}\n")
    stdscr.refresh()
    tcp_client = create_tcp_client(server_info)
    tcp_client.challange(server_info.PublicKey)
    stdscr.addstr("Keys exchanged. Starting game...\n")
    stdscr.refresh()
    return tcp_client

def login(stdscr, tcp_client):
    curses.curs_set(1)
    stdscr.clear()
    stdscr.addstr("Login to Snake Game\n")
    stdscr.addstr("Username: ")
    curses.echo()
    username = stdscr.getstr().decode('utf-8')
    stdscr.addstr("Password: ")
    password = stdscr.getstr().decode('utf-8') 
    tcp_client.login(username, password)
    login_response = json.loads(tcp_client.recv_aes())
    if not login_response['success']:
        stdscr.addstr(f"Invalid credentials, try again!\n")
        stdscr.refresh()
        time.sleep(2)
        return login(stdscr, tcp_client)
    curses.noecho()
    stdscr.clear()
    
    stdscr.addstr(f"Welcome {username}!\n")
    stdscr.refresh()
    stdscr.getch()
    return username

def main_menu(stdscr, username, tcp_client):
    while True:
        stdscr.clear()
        stdscr.addstr(f"Welcome {username}!\n")
        stdscr.addstr("1. Play Game\n")
        stdscr.addstr("2. View Last Games\n")
        stdscr.addstr("3. View High Scores\n")
        stdscr.addstr("4. Exit\n")
        stdscr.refresh()
        choice = stdscr.getch()

        if choice == ord('1'):
            score, level = play(stdscr)
            tcp_client.new_game(score, level)
            new_game_response = json.loads(tcp_client.recv_aes())
            if new_game_response['success'] != True:
                stdscr.addstr(f"Failed to save data to the server!\n")
                continue
        elif choice == ord('2'):
            view_last_games(stdscr)
        elif choice == ord('3'):
            view_high_scores(stdscr)
        elif choice == ord('4'):
            break

def view_last_games(stdscr):
    stdscr.clear()
    stdscr.addstr("Last Games:\n")
    stdscr.addstr("No games played yet.\n")
    stdscr.addstr("Press any key to return to the main menu...")
    stdscr.getch()

def view_high_scores(stdscr):
    stdscr.clear()
    stdscr.addstr("High Scores:\n")
    stdscr.addstr("No high scores yet.\n")
    stdscr.addstr("Press any key to return to the main menu...")
    stdscr.getch()
    
def main(stdscr):
    tcp_client = start_game(stdscr)
    username = login(stdscr, tcp_client)
    main_menu(stdscr, username, tcp_client)

if __name__ == "__main__":
    curses.wrapper(main)