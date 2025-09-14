import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Badge } from './components/ui/badge';
import { Alert, AlertDescription } from './components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './components/ui/dialog';
import { Progress } from './components/ui/progress';
import { Calendar, Clock, Users, Vote, CheckCircle, XCircle, Upload, BarChart3, User, Shield } from 'lucide-react';
import { toast, Toaster } from 'sonner';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = React.createContext();

const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp * 1000 > Date.now()) {
          setUser({
            id: payload.sub,
            type: payload.type,
            token: token
          });
        } else {
          localStorage.removeItem('token');
        }
      } catch (error) {
        localStorage.removeItem('token');
      }
    }
    setLoading(false);
  }, []);

  const login = (token, userType, userId) => {
    localStorage.setItem('token', token);
    setUser({ id: userId, type: userType, token });
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// Countdown Timer Component
const CountdownTimer = ({ targetDate, onComplete }) => {
  const [timeLeft, setTimeLeft] = useState('');

  useEffect(() => {
    const calculateTimeLeft = () => {
      const now = new Date().getTime();
      const target = new Date(targetDate).getTime();
      const difference = target - now;

      if (difference <= 0) {
        onComplete && onComplete();
        return 'Time expired';
      }

      const days = Math.floor(difference / (1000 * 60 * 60 * 24));
      const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((difference % (1000 * 60)) / 1000);

      return `${days}d ${hours}h ${minutes}m ${seconds}s`;
    };

    const timer = setInterval(() => {
      setTimeLeft(calculateTimeLeft());
    }, 1000);

    setTimeLeft(calculateTimeLeft());

    return () => clearInterval(timer);
  }, [targetDate, onComplete]);

  return (
    <div className="flex items-center gap-2 text-lg font-mono">
      <Clock className="h-5 w-5" />
      <span>{timeLeft}</span>
    </div>
  );
};

// Student Login Component
const StudentLogin = () => {
  const [indexNumber, setIndexNumber] = useState('');
  const [pin, setPin] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/student/login`, {
        index_number: indexNumber,
        pin: pin
      });

      login(response.data.access_token, response.data.user_type, response.data.user_id);
      toast.success('Login successful!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-xl border-0 bg-white/80 backdrop-blur-sm">
        <CardHeader className="text-center pb-8">
          <div className="mx-auto mb-4 w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center">
            <Vote className="h-8 w-8 text-blue-600" />
          </div>
          <CardTitle className="text-2xl font-bold text-gray-900">Student Login</CardTitle>
          <CardDescription className="text-gray-600">
            Enter your index number and PIN to access the voting system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Index Number</label>
              <Input
                type="text"
                value={indexNumber}
                onChange={(e) => setIndexNumber(e.target.value)}
                placeholder="Enter your index number"
                required
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">PIN</label>
              <Input
                type="password"
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder="Enter your PIN"
                required
                className="h-12"
              />
              <p className="text-xs text-gray-500">
                PIN: Your surname + last 4 digits of reference number
              </p>
            </div>
            <Button type="submit" disabled={loading} className="w-full h-12 bg-blue-600 hover:bg-blue-700">
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

// Admin Login Component
const AdminLogin = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/admin/login`, {
        username,
        password
      });

      login(response.data.access_token, response.data.user_type, response.data.user_id);
      toast.success('Admin login successful!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-slate-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-xl border-0 bg-white/80 backdrop-blur-sm">
        <CardHeader className="text-center pb-8">
          <div className="mx-auto mb-4 w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center">
            <Shield className="h-8 w-8 text-slate-600" />
          </div>
          <CardTitle className="text-2xl font-bold text-gray-900">Admin Login</CardTitle>
          <CardDescription className="text-gray-600">
            Access the election management dashboard
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Username</label>
              <Input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter admin username"
                required
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter admin password"
                required
                className="h-12"
              />
            </div>
            <Button type="submit" disabled={loading} className="w-full h-12 bg-slate-600 hover:bg-slate-700">
              {loading ? 'Signing in...' : 'Admin Sign In'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

// Login Page Component
const LoginPage = () => {
  return (
    <Tabs defaultValue="student" className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50">
      <div className="container mx-auto px-4 pt-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Department Election System</h1>
          <p className="text-gray-600">Secure digital voting for Level 100-400 students</p>
        </div>
        
        <div className="flex justify-center mb-8">
          <TabsList className="grid w-full max-w-md grid-cols-2 h-12">
            <TabsTrigger value="student" className="flex items-center gap-2">
              <User className="h-4 w-4" />
              Student
            </TabsTrigger>
            <TabsTrigger value="admin" className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Admin
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="student">
          <StudentLogin />
        </TabsContent>
        
        <TabsContent value="admin">
          <AdminLogin />
        </TabsContent>
      </div>
    </Tabs>
  );
};

// Student Dashboard Component
const StudentDashboard = () => {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const { user, logout } = useAuth();

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchStatus = async () => {
    try {
      const response = await axios.get(`${API}/student/status`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      setStatus(response.data);
    } catch (error) {
      if (error.response?.status === 401) {
        logout();
      }
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (status?.status === 'no_election') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 p-4">
        <div className="container mx-auto max-w-2xl">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Student Portal</h1>
            <Button onClick={logout} variant="outline">Logout</Button>
          </div>
          
          <Card className="text-center p-8">
            <CardContent>
              <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <CardTitle className="text-xl mb-2">No Election Scheduled</CardTitle>
              <CardDescription>
                There are currently no elections scheduled. Please check back later.
              </CardDescription>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const election = status?.election;
  const currentTime = new Date();
  const startTime = new Date(election?.start_at);
  const endTime = new Date(election?.end_at);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 p-4">
      <div className="container mx-auto max-w-4xl">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Student Portal</h1>
          <Button onClick={logout} variant="outline">Logout</Button>
        </div>

        <div className="grid gap-6">
          {/* Election Info Card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Vote className="h-6 w-6" />
                {election?.name}
              </CardTitle>
              <CardDescription>
                Election Status: <Badge variant={
                  election?.status === 'active' ? 'default' : 
                  election?.status === 'not_started' ? 'secondary' : 'destructive'
                }>
                  {election?.status === 'active' ? 'Voting Active' :
                   election?.status === 'not_started' ? 'Not Started' : 'Ended'}
                </Badge>
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-600 mb-1">Voting Period</p>
                  <p className="font-medium">
                    {new Date(election?.start_at).toLocaleString()} - {new Date(election?.end_at).toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 mb-1">Your Status</p>
                  <div className="flex items-center gap-2">
                    {status?.has_voted ? (
                      <>
                        <CheckCircle className="h-4 w-4 text-green-600" />
                        <span className="text-green-600 font-medium">Vote Submitted</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="h-4 w-4 text-orange-600" />
                        <span className="text-orange-600 font-medium">Not Voted</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Status-based Content */}
          {election?.status === 'not_started' && (
            <Card>
              <CardHeader>
                <CardTitle>Voting Hasn't Started Yet</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <Clock className="h-16 w-16 text-blue-600 mx-auto mb-4" />
                  <p className="text-lg mb-4">Voting will begin in:</p>
                  <CountdownTimer targetDate={election.start_at} />
                </div>
              </CardContent>
            </Card>
          )}

          {election?.status === 'active' && !status?.has_voted && (
            <Card>
              <CardHeader>
                <CardTitle>Cast Your Vote</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="text-center">
                    <p className="text-lg mb-4">Voting ends in:</p>
                    <CountdownTimer targetDate={election.end_at} />
                  </div>
                  <Button 
                    onClick={() => window.location.href = '/ballot'} 
                    className="w-full h-12 bg-blue-600 hover:bg-blue-700"
                  >
                    Go to Ballot
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {election?.status === 'active' && status?.has_voted && (
            <Card>
              <CardHeader>
                <CardTitle>Vote Submitted Successfully</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
                  <p className="text-lg mb-4">You have successfully cast your vote!</p>
                  <p className="text-gray-600 mb-4">Please wait for the results to be published.</p>
                  <div>
                    <p className="text-sm text-gray-600 mb-2">Voting ends in:</p>
                    <CountdownTimer targetDate={election.end_at} />
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {election?.status === 'ended' && (
            <Card>
              <CardHeader>
                <CardTitle>Election Ended</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  {status?.has_voted ? (
                    <>
                      <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
                      <p className="text-lg text-green-600 font-medium mb-2">
                        You successfully cast your vote!
                      </p>
                      <p className="text-gray-600">Thank you for participating. Results will be published soon.</p>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-16 w-16 text-red-600 mx-auto mb-4" />
                      <p className="text-lg text-red-600 font-medium mb-2">
                        You did not cast your vote
                      </p>
                      <p className="text-gray-600">The voting period has ended.</p>
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

// Admin Dashboard Component
const AdminDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const { user, logout } = useAuth();

  useEffect(() => {
    fetchDashboard();
  }, []);

  const fetchDashboard = async () => {
    try {
      const response = await axios.get(`${API}/admin/dashboard`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      setDashboardData(response.data);
    } catch (error) {
      if (error.response?.status === 401) {
        logout();
      }
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-slate-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-slate-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-slate-50 p-4">
      <div className="container mx-auto max-w-6xl">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Admin Dashboard</h1>
          <Button onClick={logout} variant="outline">Logout</Button>
        </div>

        <div className="grid gap-6">
          {/* Statistics Cards */}
          <div className="grid md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-3">
                  <Users className="h-8 w-8 text-blue-600" />
                  <div>
                    <p className="text-sm text-gray-600">Total Students</p>
                    <p className="text-2xl font-bold">{dashboardData?.statistics?.total_students || 0}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-8 w-8 text-green-600" />
                  <div>
                    <p className="text-sm text-gray-600">Votes Cast</p>
                    <p className="text-2xl font-bold">{dashboardData?.statistics?.students_voted || 0}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-3">
                  <XCircle className="h-8 w-8 text-orange-600" />
                  <div>
                    <p className="text-sm text-gray-600">Not Voted</p>
                    <p className="text-2xl font-bold">{dashboardData?.statistics?.students_not_voted || 0}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center gap-3">
                  <BarChart3 className="h-8 w-8 text-purple-600" />
                  <div>
                    <p className="text-sm text-gray-600">Turnout</p>
                    <p className="text-2xl font-bold">{dashboardData?.statistics?.turnout_percentage?.toFixed(1) || 0}%</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Current Election Status */}
          {dashboardData?.election ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Vote className="h-6 w-6" />
                  Current Election: {dashboardData.election.name}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid md:grid-cols-3 gap-4">
                  <div>
                    <p className="text-sm text-gray-600 mb-1">Status</p>
                    <Badge variant={
                      dashboardData.election.status === 'active' ? 'default' : 
                      dashboardData.election.status === 'not_started' ? 'secondary' : 'destructive'
                    }>
                      {dashboardData.election.status === 'active' ? 'Active' :
                       dashboardData.election.status === 'not_started' ? 'Not Started' : 'Ended'}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 mb-1">Start Time</p>
                    <p className="font-medium">{new Date(dashboardData.election.start_at).toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 mb-1">End Time</p>
                    <p className="font-medium">{new Date(dashboardData.election.end_at).toLocaleString()}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="text-center py-12">
                <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <CardTitle className="text-xl mb-2">No Active Election</CardTitle>
                <CardDescription className="mb-4">
                  Create a new election to get started
                </CardDescription>
                <Button className="bg-slate-600 hover:bg-slate-700">
                  Create Election
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-3 gap-4">
                <Button className="h-16 flex flex-col gap-2" variant="outline">
                  <Upload className="h-6 w-6" />
                  Upload Students
                </Button>
                <Button className="h-16 flex flex-col gap-2" variant="outline">
                  <Vote className="h-6 w-6" />
                  Manage Elections
                </Button>
                <Button className="h-16 flex flex-col gap-2" variant="outline">
                  <BarChart3 className="h-6 w-6" />
                  View Results
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={
          user.type === 'admin' ? <AdminDashboard /> : <StudentDashboard />
        } />
        <Route path="/ballot" element={
          user.type === 'student' ? <div>Ballot Page (Coming Soon)</div> : <Navigate to="/" />
        } />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  );
}

// Wrap App with AuthProvider
const AppWithAuth = () => (
  <AuthProvider>
    <App />
    <Toaster position="top-right" />
  </AuthProvider>
);

export default AppWithAuth;