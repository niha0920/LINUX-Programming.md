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
- fork() is a system call used to create a new child process.
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
        printf("Fork failed\n");
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
    printf("After fork() - Executing in both parent and child\n");
    return 0;
}
```

## 4. What is the purpose of the wait() system call in process management? 
- wait() is used by a parent process to wait for its child process to terminate.
- It ensures that the parent retrieves the child’s exit status.
- Prevents the creation of zombie processes (terminated child processes that still occupy system resources).
- If multiple child processes exist, wait() can wait for any one of them to finish.
- Returns the PID of the terminated child to the parent.
- If no child has terminated yet, the parent is blocked until a child finishes.
- wait() is often used in combination with fork() and exec() to ensure proper process synchronization.

## 5. Describe the role of the exec() family of functions in process management.
- The exec() family of functions is used to run a new program within an existing process.
- It replaces the current process image (code, data, and stack) with a new program.
- After a successful exec(), the original program stops executing, and the new program starts.
- It allows a process to execute a different program without creating a new process.
- Commonly used in combination with fork():
  - Parent continues execution.
  - Child calls exec() to run a new program.
- Variants include: execl(), execv(), execle(), execve(), execlp(), execvp() – differ in how arguments and environment variables are passed.
- Returns only if there is an error (otherwise, the new program runs and control never returns).
- Helps implement features like shell commands execution, where each command runs as a separate program.

## 6. Write a C program to illustrate the use of the execvp() function.
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
int main() 
{
    pid_t pid;
    int status;
    pid = fork();  // Create a child process
    if(pid < 0) 
    {
        printf("Fork failed\n");
        return 1;
    }
    else if(pid == 0) 
    {
        char *args[] = {"ls", "-l", NULL};  // Command and arguments
        printf("Child process running execvp()\n");
        // Replace child process with 'ls -l' command
        if(execvp("ls", args) < 0) 
        {
            printf("execvp failed\n");
        }
    }
    else 
    {
        // Parent process waits for child to finish
        wait(&status);
        printf("Parent process: Child finished execution\n");
    }
    return 0;
}
```

## 7. How does the vfork() system call differ from fork()?
### fork() 
- Creates a new child process with a copy of the parent's address space.
- Parent and child have separate copies of data, stack, and heap.
- Parent and child run independently after fork.
- Slower, since it duplicates the entire process memory (through modern OSs use copy-on-write optimization).
- Safe to use for general multitasking.
### vfork()
- Creates a child process without copying the parent's address space (for efficiency). It is meant to be used when the child immediately calls exec() or _exit().
- Child shares the address space of the parent until it calls exex() or _exit() -> so child must not modify variables or return from the function.
- Parent is suspended until the child calls exec() or _exit().
- Faster, as no memory duplication occurs.\
- Unsafe if child modifies memory before exec() / _exit().

## 8. Discuss the significance of the getpid() and getppid() system calls.
### getpid()
- Returns the process ID (PID) of the calling process.
- Every process in the system has a unique PID.
- Useful for identifying processes in logs, debugging, or sending signals (kill(pid, signal)).
Example: If a process calls getpid() and receives 1234, then its PID is 1234.
### getppid()
- Returns the parent process ID (PPID) of the calling process.
- Helps a child process know who its parent is.
- If the parent terminates before the child, the child’s PPID becomes 1 (the init process adopts it).
Example: If the parent has PID 1000, the child calling getppid() gets 1000.

## 9. Explain the concept of process termination in UNIX-like operating systems.
Process termination means ending the execution of a process and releasing its resources (CPU, memory, file descriptors, etc.) back to the operating system.
### Ways a Process Can Terminate
#### Normal termination (voluntary):
- Process finishes execution and calls exit() system call.
- Example: return 0; in main() implicitly calls exit(0).
#### Abnormal termination (voluntary):
- Process detects an error and calls abort() or exit(status != 0).
#### Killed by a signal (involuntary):
- Another process or the OS kills it using signals like SIGKILL or SIGTERM.
#### Parent termination:
- If a parent terminates before its child, the child becomes an orphan and is adopted by init (PID 1).

## 10. Write a program in C to create a child process using fork() and print its PID.
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main() 
{
    pid_t pid;
    pid = fork();
    if(pid < 0) 
    {
        printf("Fork failed.\n");
        return 1;
    }
    else if(pid == 0) 
    {
        printf("Child Process: PID = %d\n", getpid());
    }
    else 
    {
        printf("Parent Process: Created Child with PID = %d\n", pid);
    }
    return 0;
}
```
