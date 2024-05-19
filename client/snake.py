import curses
import random
from curses import textpad


def create_food(snake, displayBox):
    food = None
    while food is None:
        food = [random.randint(displayBox[0][0]+1, displayBox[1][0]-1), random.randint(displayBox[0][1]+1, displayBox[1][1]-1)]
        if food in snake:
            food = None
    return food

def print_score(stdsrc, screenWidth, score):
    score_msg = f'SCORE: {score}'
    stdsrc.addstr(1, screenWidth // 2 - len(score_msg) // 2, score_msg)
    # stdsrc.refresh()

def main(stdscr):
    curses.curs_set(0)
    # like sleep in while 1:
    stdscr.timeout(150)
    screenHeight, screenWidth = stdscr.getmaxyx()

    # corner values
    displayBox = [[3, 3], [screenHeight - 3, screenWidth -3]]

    textpad.rectangle(stdscr, displayBox[0][0], displayBox[0][1], displayBox[1][0], displayBox[1][1])

    #  the head is the first value
    snake = [[ screenHeight // 2, screenWidth // 2 + 1 ], [screenHeight // 2, screenWidth // 2], [screenHeight // 2, screenWidth // 2 - 1 ]]
    
    score = 0
    print_score(stdscr, screenWidth, score)
    
    
    # direction where snake needs to go - default is right
    direction = curses.KEY_RIGHT


    for y, x in snake:
        stdscr.addstr(y, x, "#")
        # stdscr.refresh()


    food = create_food(snake, displayBox)
    stdscr.addstr(food[0], food[1], "*")

    while True:
        previous_direction = direction
        # we are blocking the key for only 150 by default - then runs the loop what keeps snake moving
        key = stdscr.getch()

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

        if snake[0] == food:
            food = create_food(snake, displayBox)
            stdscr.addstr(food[0], food[1], "*")
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

curses.wrapper(main)