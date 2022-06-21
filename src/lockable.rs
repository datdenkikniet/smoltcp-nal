pub trait Lockable {
    type T;
    fn lock<FN, R>(&mut self, func: FN) -> R
    where
        FN: FnOnce(&mut Self::T) -> R;
}

impl<S, T> Lockable for S
where
    S: rtic::Mutex<T = T>,
{
    type T = T;
    fn lock<FN, R>(&mut self, func: FN) -> R
    where
        FN: FnOnce(&mut T) -> R,
    {
        self.lock(|l| func(l))
    }
}

pub struct Exclusive<'a, T>(&'a mut T);

impl<'a, T> From<&'a mut T> for Exclusive<'a, T> {
    fn from(me: &'a mut T) -> Self {
        Self(me)
    }
}

impl<'a, T> Lockable for Exclusive<'a, T> {
    type T = T;

    fn lock<FN, R>(&mut self, func: FN) -> R
    where
        FN: FnOnce(&mut Self::T) -> R,
    {
        func(self.0)
    }
}
