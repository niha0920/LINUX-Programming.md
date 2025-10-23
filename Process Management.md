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
- Faster, as no memory duplication occurs.
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

## 11. Describe the process hierarchy in UNIX-like operating systems.
- In UNIX-like systems, processes are organized in a hierarchical (tree-like) structure, where each process is created by another process (its parent).
- This parent–child relationship forms the process hierarchy.
- The hierarchy ensures process control, resource management, and cleanup (via wait() and exec() mechanisms).
### Root of the Hierarchy – init / systemd
- The very first process started by the kernel after booting is init (or systemd in modern systems).
- It has PID = 1.
- All other processes are descendants of init.
### Parent and Child Processes
- When a process calls the fork() system call, it creates a child process.
- he parent continues executing, and the child runs a copy of the parent’s program (or a new one via exec()).
- Every process keeps a record of its Parent Process ID (PPID).
### Process Tree Structure
- The relationship between parent and child processes forms a process tree.
- You can visualize it using the command:
  ```c
  ps -ef --forest
  ```
### Orphan and Zombie Processes
- If a parent terminates before the child → the child becomes an orphan and is adopted by init.
- If a child terminates but the parent hasn’t read its exit status → it becomes a zombie (defunct) process.

## 12. What is the purpose of the exit() function in C programming?
- The exit() function is used to terminate a program normally in C.
- It is declared in the header file <stdlib.h>.
### Purpose / Functionality
- Terminates the program immediately.
- Performs cleanup operations before termination:
  - Closes all open files.
  - Flushes all output buffers.
  - Calls functions registered with atexit().
  - Returns a status code to the operating system.
### Syntax
```c
void exit(int status);
```
- status → an integer value returned to the operating system.
  - 0 → successful termination
  - Non-zero → abnormal/error termination

## 13. Explain how the execve() system call works and provide a code example.
- execve() is a system call used to execute a new program within the current process.
- It replaces the current process image with a new program image, meaning the calling process is completely overwritten.
- It does not create a new process (unlike fork()); instead, it transforms the existing one.
### Syntax
```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```
- pathname → Path to the executable file (e.g., /bin/ls)
- argv[] → Argument list (like command-line arguments), must end with NULL
- envp[] → List of environment variables, must end with NULL
### Working of execve()
- The current process calls execve().
- The kernel:
  - Loads the new program into memory.
  - Replaces the current process’s code, data, and stack with the new program’s image.
  - Starts executing the new program from its main().
- If successful, execve() does not return.
- If it fails (e.g., file not found or permission denied), it returns -1.
```c
#include <stdio.h>
#include <unistd.h>
int main()
{
    char *args[] = {"/bin/ls", "-l", NULL};   // program and arguments
    char *envp[] = {NULL};   // environment variables
    printf("Before execve()\n");
    // Replace current process with 'ls -l' command
    if(execve("/bin/ls", args, envp) == -1)
    {
        perror("execve failed");
    }
    printf("This line will not execute if execve succeeds\n");
    return 0;
}
```

## 14. Discuss the role of the fork() system call in implementing multitasking.
- fork() is a system call in UNIX-like operating systems used to create a new process.
- The new process created is called the child process, and the original is the parent process.
### Purpose in Multitasking
- Multitasking means executing multiple processes concurrently.
- fork() enables multitasking by allowing multiple independent processes to run at the same time.
- Each process (parent and child) has its own address space, registers, and execution flow, allowing parallel execution.
### How It Enables Multitasking
- The parent and child processes can run different tasks simultaneously.
- The OS scheduler switches between them, giving each process CPU time.
- Example:
  - Parent handles user input.
  - Child performs background computation or I/O.

## 15. Write a C program to create multiple child processes using fork() and display their PIDs.
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main()
{
    pid_t pid;
    int n;
    printf("Enter number of child proocesses to create : ");
    scanf("%d", &n);
    for(int i = 0; i < n; i++)
    {
        pid = fork();
        if(pid < 0)
        {
            printf("Fork failed.\n");
            return 1;
        }
        else if(pid == 0)
        {
            printf("Child %d created with PID: %d, Parent PID: %d\n", i + 1, getpid(), getppid());
            return 0;   // child exits after printing to prevent further forks
        }
        // Parent continues the loop to create next child
    }
    printf("Parent process (PID: %d) created %d child processes.\n", getpid(), n);   // Only the parent reaches this point after creating all children
    return 0;
}
```

## 16. How does the exec() system call replace the current process image with a new one?
- The exec() family of system calls (execl(), execv(), execvp(), execve(), etc.) is used to replace the current process image with a new program image.
- It does not create a new process; instead, it transforms the existing process into a new one.
### Concept of Process Image
A process image consists of:
- Program code (text segment)
- Data segment (global/static variables)
- Heap (dynamically allocated memory)
- Stack (function calls, local variables)
#### When exec() is called, all these sections are replaced by the new program’s image loaded from the executable file.
### Working Steps of exec()
1. The current process calls an exec() function (e.g., execve("/bin/ls", args, envp)).
2. The kernel performs the following actions:
- Loads the new executable file into the process’s memory.
- Erases the old code, data, stack, and heap of the current process.
- Initializes the new program’s stack, heap, and environment.
- Sets up the program counter (PC) to point to the new program’s main() function.
3. After a successful exec(), the new program starts executing immediately.
- The process ID (PID) remains the same, but the program content changes.
4. exec() does not return on success — only on failure (returns -1).

## 17. Explain the concept of process scheduling in operating systems.
- Process scheduling is the activity of the operating system that decides which process runs on the CPU next.
- It ensures that CPU time is shared efficiently among all processes to achieve maximum CPU utilization, fairness, and responsive multitasking.
### Purpose of Process Scheduling
- To maximize CPU utilization (CPU should never be idle).
- To ensure fairness — every process gets a fair share of CPU time.
- To provide fast response time for interactive users.
- To maintain system stability and throughput.
### Types of Scheduling
- a) Long-Term Scheduler (Job Scheduler):
  - Decides which processes should be admitted to the system for execution.
  - Controls the degree of multiprogramming (number of processes in memory).
- b) Short-Term Scheduler (CPU Scheduler):
  - Decides which ready process gets the CPU next.
  - Runs frequently (milliseconds).
- c) Medium-Term Scheduler (Swapper):
  - Temporarily removes processes from memory (swapping) to reduce load and later resumes them.
### Scheduling Criteria
- CPU utilization → keep CPU busy as much as possible.
- Throughput → number of processes completed per unit time.
- Turnaround time → total time taken to execute a process.
- Waiting time → total time a process spends waiting in the ready queue.
- Response time → time from request submission to first response.
### Scheduling Algorithms
- First Come First Serve (FCFS): Processes executed in order of arrival.
- Shortest Job Next (SJN): Shortest process executed first.
- Round Robin (RR): Each process gets a fixed time slice (quantum).
- Priority Scheduling: CPU allocated based on priority value.
- Multilevel Queue Scheduling: Multiple queues for different process types (foreground, background, etc.).
### Example Scenario
Suppose three processes arrive:
- P1 (burst time = 4), P2 (burst = 3), P3 (burst = 2).
- A Round Robin scheduler with time quantum = 2 will switch between them in order (P1→P2→P3→P1→P2), ensuring fair CPU sharing.

## 18. Describe the role of the clone() system call in process management.
- clone() is a Linux-specific system call used to create a new process (or thread) similar to fork(), but with more control over what the child process shares with the parent.
- It is the foundation of thread creation in Linux (used internally by pthread_create()).
### Purpose
- To create lightweight processes or threads that can share parts of the execution context (memory, file descriptors, etc.) with the parent process.
- Provides fine-grained control over resource sharing between parent and child.
### Syntax
```c
int clone(int (*fn)(void *), void *child_stack, int flags, void *arg);
```
- fn: Function that the child process will execute.
- child_stack: Pointer to the top of the child’s stack space.
- flags: Controls what resources are shared between parent and child.
- arg: Argument passed to the child function.
### Common Flags
- CLONE_VM → Parent and child share the same memory space.
- CLONE_FILES → Share file descriptors.
- CLONE_FS → Share filesystem information (current directory, root, etc.).
- CLONE_SIGHAND → Share signal handlers.
- CLONE_THREAD → Place the child in the same thread group as the parent (used for threads).
### How It Differs from fork()
| Feature          |	fork()                     |	clone()                           |
| ---------------- | --------------------------- | ---------------------------------- |
| Memory space     |	Separate copy              |	Can share with parent (CLONE_VM)  |
| Threads          |	Creates a separate process |	Can create threads (CLONE_THREAD) |
| Resource sharing |	Minimal                    |	Customizable via flags            |
| Portability      |	Standard (POSIX)           |	Linux-specific                    |

## 19. Write a program in C to create a zombie process and explain how to avoid it.
```c
#include<stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main()
{
    pid_t pid = fork();
    if(pid < 0)
    {
        perror("fork failed");
        exit(1);
    }
    else if(pid == 0)
    {
        printf("Child process running... PID = %d\n", getpid());
        printf("Child exiting now.\n");
        exit(0);   // Child terminates immediately
    }
    else
    {
        printf("Parent process PID = %d\n", getpid());
        printf("Child process created with PID = %d\n", pid);
        printf("Parent sleeping for 10 seconds...\n");
        sleep(10);   // During this time, child becomes zombie
        printf("Parent exiting now.\n");
    }
    return 0;
}
```
### Why Zombie Occurs
- The parent process does not call wait() or waitpid() to collect the child’s exit status.
- The kernel keeps the child’s entry in the process table until the parent retrieves the status.
### How to Avoid a Zombie Process
- Use wait() or waitpid()
- Ensure the parent calls wait() to read the child’s exit status.

## 20. Discuss the significance of the setuid() and setgid() system calls in process man
- setuid() → Sets the User ID (UID) of the calling process.
- setgid() → Sets the Group ID (GID) of the calling process.
- These system calls are used to change the effective user or group identity of a process during execution.
### Purpose
- They control process privileges and access permissions.
- Allow a process to temporarily switch user/group identities — typically to perform privileged operations securely.
- Commonly used in set-user-ID (SUID) and set-group-ID (SGID) programs.
### Syntax
```c
#include <unistd.h>
int setuid(uid_t uid);
int setgid(gid_t gid);
```
- uid / gid → The new user ID or group ID to assign.
- Return 0 on success, -1 on failure.
### How It Works
- Every process in Linux has three IDs:
  - Real UID/GID: Original user or group that started the process.
  - Effective UID/GID: Determines access permissions for files and resources.
  - Saved UID/GID: Used to temporarily drop and regain privileges.
- setuid() and setgid() allow a process to change its effective IDs, controlling what resources it can access.
### Use Case Example
- SUID Programs (like passwd):
  - /usr/bin/passwd is owned by root and has the SUID bit set.
  - When executed by a normal user, it runs with root privileges (effective UID = 0).
  - Internally, setuid() ensures the process runs with those elevated privileges temporarily to modify system files like /etc/shadow.
### Security Aspect
- setuid() and setgid() help implement privilege separation — allowing only specific tasks to run with higher privileges.
- Incorrect use can lead to security vulnerabilities (privilege escalation).

## 21. Explain the concept of process groups and their significance in UNIX-like operating systems.
- A process group is a collection of one or more processes that are related and can be managed together by the operating system.
- Each process group is identified by a unique Process Group ID (PGID).
- Typically, a process group is created when a user starts a command in the shell — all related processes of that command belong to the same group.
### Purpose
- Process groups are used to control and manage multiple related processes as a single unit.
- They help in:
  - Job control (in terminals or shells).
  - Signal distribution (sending signals like SIGINT, SIGSTOP to all processes in a group).
  - Foreground and background process management.
### Structure
- Each process has:
  - PID (Process ID): unique identifier of the process.
  - PGID (Process Group ID): identifier of the process group it belongs to.
- The first process in the group (usually the process that created others) is the group leader.
### System Calls Related to Process Groups
| Function           | Description                                   |
| ------------------ | --------------------------------------------- |
| getpgrp()          | Gets the PGID of the calling process.         |
| setpgid(pid, pgid) | Sets the PGID for a process.                  |
| getpgid(pid)       | Gets the PGID of a specified process.         |
| killpg(pgid, sig)	 | Sends a signal to all processes in the group. |

## 22. Write a C program to demonstrate the use of the waitpid() function for process synchronization.
