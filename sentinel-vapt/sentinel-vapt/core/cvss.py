class CVSSv3:
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    AC = {'L': 0.77, 'H': 0.44}
    PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.5}
    UI = {'N': 0.85, 'R': 0.62}
    S = {'U': 'U', 'C': 'C'}
    CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}

    @staticmethod
    def roundup(value):
        return min((int(value * 10 + 0.000001) + (1 if (value * 10) % 1 > 0 else 0)) / 10.0, 10.0)

    @classmethod
    def score(cls, av='N', ac='L', pr='N', ui='N', s='U', c='L', i='L', a='L'):
        iss = 1 - ((1 - cls.CIA[c]) * (1 - cls.CIA[i]) * (1 - cls.CIA[a]))
        impact = 6.42 * iss if s == 'U' else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        pr_val = cls.PR_U[pr] if s == 'U' else cls.PR_C[pr]
        exploitability = 8.22 * cls.AV[av] * cls.AC[ac] * pr_val * cls.UI[ui]
        if impact <= 0:
            return 0.0
        if s == 'U':
            return cls.roundup(min(impact + exploitability, 10))
        return cls.roundup(min(1.08 * (impact + exploitability), 10))

    @staticmethod
    def severity(score):
        if score == 0:
            return 'Info'
        if score < 4.0:
            return 'Low'
        if score < 7.0:
            return 'Medium'
        if score < 9.0:
            return 'High'
        return 'Critical'
