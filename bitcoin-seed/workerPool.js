
(function()
{
    const cpuCoreCount = navigator.hardwareConcurrency;
    let busyWorkers = new Set();

    const workers = new Array(cpuCoreCount);

    for (let i = 0; i < cpuCoreCount; ++i)
        workers[i] = new Worker("worker.js");

    const waitingTasks = [];

    const EnqueueWorkerTask = function(data, callback)
    {
        let selectedWorker;
        let selectedIndex;
        for (let i = 0; i < cpuCoreCount; ++i)
        {
            if (!busyWorkers.has(i))
            {
                selectedWorker = workers[i];
                selectedIndex = i;
                busyWorkers.add(i);
                break;
            }
        }

        if (!selectedWorker)
        {
            waitingTasks.push([data, callback]);
            return;
        }

        selectedWorker.postMessage(data);
        selectedWorker.onmessage = ev =>
        {
            busyWorkers.delete(selectedIndex);

            if (waitingTasks.length !== 0)
            {
                const task = waitingTasks.shift();
                EnqueueWorkerTask(task[0], task[1]);
            }
            
            callback(ev.data);
        };
    };

    window.EnqueueWorkerTask = EnqueueWorkerTask;
})();