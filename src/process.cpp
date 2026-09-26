// SPDX-License-Identifier: Apache-2.0
#include "process.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <optional>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace coretrace::runtime_analyzer
{
#if defined(_WIN32)
    ProcessResult RunProcess(const ProcessSpec&)
    {
        ProcessResult result;
        result.error = "runtime execution is not implemented on Windows yet";
        return result;
    }
#else
    namespace
    {
        [[nodiscard]] bool SetCloseOnExec(int fd)
        {
            const int flags = fcntl(fd, F_GETFD);
            if (flags < 0)
            {
                return false;
            }
            return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
        }

        [[nodiscard]] bool SetNonBlocking(int fd)
        {
            const int flags = fcntl(fd, F_GETFL);
            if (flags < 0)
            {
                return false;
            }
            return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
        }

        void AppendFromFd(int fd, std::string& output, bool& open)
        {
            char buffer[4096];
            for (;;)
            {
                const ssize_t count = read(fd, buffer, sizeof(buffer));
                if (count > 0)
                {
                    output.append(buffer, static_cast<std::size_t>(count));
                    continue;
                }
                if (count == 0)
                {
                    close(fd);
                    open = false;
                    return;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return;
                }
                close(fd);
                open = false;
                return;
            }
        }

    } // namespace

    ProcessResult RunProcess(const ProcessSpec& spec)
    {
        ProcessResult result;
        int stdout_pipe[2] = {-1, -1};
        int stderr_pipe[2] = {-1, -1};
        if (pipe(stdout_pipe) != 0)
        {
            result.error = std::string("pipe failed: ") + std::strerror(errno);
            return result;
        }
        if (pipe(stderr_pipe) != 0)
        {
            result.error = std::string("pipe failed: ") + std::strerror(errno);
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
            return result;
        }

        (void)SetCloseOnExec(stdout_pipe[0]);
        (void)SetCloseOnExec(stderr_pipe[0]);
        (void)SetNonBlocking(stdout_pipe[0]);
        (void)SetNonBlocking(stderr_pipe[0]);

        const pid_t pid = fork();
        if (pid < 0)
        {
            result.error = std::string("fork failed: ") + std::strerror(errno);
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
            close(stderr_pipe[0]);
            close(stderr_pipe[1]);
            return result;
        }

        if (pid == 0)
        {
            // Own process group, so that a timeout also stops the programs it forks.
            (void)setpgid(0, 0);
            close(stdout_pipe[0]);
            close(stderr_pipe[0]);
            (void)dup2(stdout_pipe[1], STDOUT_FILENO);
            (void)dup2(stderr_pipe[1], STDERR_FILENO);
            close(stdout_pipe[1]);
            close(stderr_pipe[1]);
            const int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd >= 0)
            {
                (void)dup2(null_fd, STDIN_FILENO);
                close(null_fd);
            }

            if (!spec.working_directory.empty() && chdir(spec.working_directory.c_str()) != 0)
            {
                _exit(126);
            }

            for (const std::string& assignment : spec.environment)
            {
                const std::size_t eq = assignment.find('=');
                if (eq != std::string::npos && eq != 0)
                {
                    std::string name = assignment.substr(0, eq);
                    std::string value = assignment.substr(eq + 1);
                    setenv(name.c_str(), value.c_str(), 1);
                }
            }

            std::vector<std::string> argv_storage;
            argv_storage.reserve(spec.args.size() + 1);
            argv_storage.push_back(spec.executable);
            argv_storage.insert(argv_storage.end(), spec.args.begin(), spec.args.end());

            std::vector<char*> argv;
            argv.reserve(argv_storage.size() + 1);
            for (std::string& arg : argv_storage)
            {
                argv.push_back(arg.data());
            }
            argv.push_back(nullptr);

            execv(spec.executable.c_str(), argv.data());
            _exit(errno == ENOENT ? 127 : 126);
        }

        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        using Clock = std::chrono::steady_clock;
        std::optional<Clock::time_point> deadline;
        if (spec.timeout > std::chrono::milliseconds(0))
        {
            deadline = Clock::now() + spec.timeout;
        }

        bool stdout_open = true;
        bool stderr_open = true;
        while (stdout_open || stderr_open)
        {
            fd_set read_set;
            FD_ZERO(&read_set);
            int max_fd = -1;
            if (stdout_open)
            {
                FD_SET(stdout_pipe[0], &read_set);
                max_fd = std::max(max_fd, stdout_pipe[0]);
            }
            if (stderr_open)
            {
                FD_SET(stderr_pipe[0], &read_set);
                max_fd = std::max(max_fd, stderr_pipe[0]);
            }

            timeval remaining{};
            timeval* wait = nullptr;
            if (deadline)
            {
                const auto left = std::max(*deadline - Clock::now(), Clock::duration::zero());
                const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(left);
                remaining.tv_sec = static_cast<time_t>(micros.count() / 1000000);
                remaining.tv_usec = static_cast<suseconds_t>(micros.count() % 1000000);
                wait = &remaining;
            }

            const int selected = select(max_fd + 1, &read_set, nullptr, nullptr, wait);
            if (selected < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                result.error = std::string("select failed: ") + std::strerror(errno);
                break;
            }
            if (selected == 0)
            {
                // Deadline: kill the group, keep what was printed, stop reading.
                (void)kill(-pid, SIGKILL);
                result.timed_out = true;
                if (stdout_open)
                {
                    AppendFromFd(stdout_pipe[0], result.stdout_text, stdout_open);
                }
                if (stderr_open)
                {
                    AppendFromFd(stderr_pipe[0], result.stderr_text, stderr_open);
                }
                break;
            }

            if (stdout_open && FD_ISSET(stdout_pipe[0], &read_set))
            {
                AppendFromFd(stdout_pipe[0], result.stdout_text, stdout_open);
            }
            if (stderr_open && FD_ISSET(stderr_pipe[0], &read_set))
            {
                AppendFromFd(stderr_pipe[0], result.stderr_text, stderr_open);
            }
        }

        if (stdout_open)
        {
            close(stdout_pipe[0]);
        }
        if (stderr_open)
        {
            close(stderr_pipe[0]);
        }

        int status = 0;
        while (waitpid(pid, &status, 0) < 0)
        {
            if (errno != EINTR)
            {
                result.error = std::string("waitpid failed: ") + std::strerror(errno);
                return result;
            }
        }

        if (WIFEXITED(status))
        {
            result.exit_code = WEXITSTATUS(status);
        }
        else if (WIFSIGNALED(status))
        {
            result.exit_code = 128 + WTERMSIG(status);
        }
        else
        {
            result.exit_code = 1;
        }

        return result;
    }
#endif
} // namespace coretrace::runtime_analyzer
