## 1. Explain the concept of process creation in operating systems. 
- A process is a program in execution.
- A new process is created by an existing process -> parent creates child.
- The first process in UNIX/Linux is init (PID = 1).
- Parent process starts execution from main().
- Child process starts execution from the point where fork() is called.
- fork() is executed twice: once in parent, once in the child.
- Return values of fork() :
  - 0 -> returned to the child process.
  - Child PID -> returned to the parent process.
- After creation, the child may call exec() to load and run a new program.
- Parent may either continue execution in parallel or wait for the child to terminate.
- OS maintains a Process Control Block (PCB) for each process to track its state, resources, and execution context.

## 2. Differentiate between the fork() and exec() system calls.
### fork()
- fork() is a syatem call used to create a new child process.
- Allows multitasking by running a new process alongside the parent.
- Child process copies the memory segments of the parent process; both run independently.
- fork() returns twice:
  - 0 in the child process
  - child PID in the parent process
- Child process gets its own unique PID.
- Parent and child communicate using inter-process communication (IPC) methods like pipes, signals, or shared memory.
- Commonly used in combination with exec() to run a new program in the child process.
### exec()
- exec() family of system calls is used to run a new program in a process.
- Replaces the current process image with a different program.
- Overwrites the process’s memory and code with the new program.
- Does not return on success; returns -1 only if there is an error.
- Can pass arguments and environment variables to the new program.
- Useful for implementing shell commands, where a child process executes a program while the parent continues.
- Multiple variants exist: execl(), execv(), execle(), execve(), execlp(), execvp() – each with slightly different ways to pass arguments and environment.

## 3. Write a C program to demonstrate the use of fork() system call.
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main() 
{
    pid_t pid;
    printf("Before fork()\n");
    pid = fork();   // Create a child process
    if(pid < 0) 
    {
        printf("Fork failed.\n");
        return 1;
    }
    else if(pid == 0) 
    {
        printf("This is the child process with PID : %d\n", getpid());
    }
    else 
    {
        printf("This is the parent process with PID : %d, Child PID : %d\n", getpid(), pid);
    }
    printf("After fork() - Executing in both parent and child.\n");
    return 0;
}
```
